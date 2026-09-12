# Méthodologie — vulnscan

## Vue d'ensemble

vulnscan combine deux grandes familles d'analyse — statique et dynamique — pour détecter six classes de vulnérabilités dans des binaires ELF x86-64 Linux. L'outil suit un pipeline en cinq étapes, chaque étape enrichissant la connaissance accumulée sur le binaire cible.

```
Binaire ELF
    │
    ├─→ [1] Parsing ELF              (lief 1.0)
    │        arch, sections, segments, symboles, PLT
    │
    ├─→ [2] Protections              (lief + pwntools)
    │        NX, Canary, RELRO, PIE, Fortify, RPATH
    │
    ├─→ [3] Analyse statique
    │        ├─ Fonctions dangereuses (CALL vers PLT stubs)
    │        ├─ Analyse de frame      (tailles de buffers, longueurs d'arguments)
    │        └─ Taint intra-procédural (sources → puits via registres + pile)
    │
    ├─→ [4] Analyse dynamique
    │        ├─ Fuzzing               (5 stratégies, pwntools cyclic)
    │        └─ Triage GDB            (RIP, offset, exploitability)
    │
    └─→ [5] Corrélation + Rapport
             (JSON + HTML Jinja2)
```

## Phase 1 — Parsing ELF

Le parsing repose sur **lief 1.0** (API incompatible avec lief 0.x). Les informations extraites sont :

- **Architecture** : `binary.header.machine_type` → `ARCH.X86_64`
- **Type** : `Header.FILE_TYPE.DYN` pour les PIE, `EXEC` pour les binaires statiques
- **Classe** : `Header.CLASS.ELF64` / `ELF32`
- **PLT map** : table `stub_addr → nom_de_fonction` construite en désassemblant `.plt.sec` (IBT/CET moderne), `.plt.got` et `.plt` classique avec Capstone
- **Symboles** : fonctions exportées avec leurs adresses de début et de fin pour `function_at(addr)`

### Résolution des stubs PLT (IBT)

Les compilateurs modernes (gcc ≥ 9 avec `-fcf-protection`) génèrent des stubs CET dans `.plt.sec` :

```asm
endbr64
bnd jmp  qword ptr [rip + 0x2f9b]   ; → GOT[printf]
```

vulnscan désassemble `.plt.sec`, identifie les instructions `jmp`/`bnd jmp` à opérande mémoire `[rip+N]`, calcule `rip + N + 4` (adresse de la prochaine instruction après le JMP) pour obtenir l'entrée GOT, puis résout cette entrée vers le symbole via la table de relocation `.rela.plt`.

## Phase 2 — Détection des protections

| Protection | Méthode de détection |
|------------|---------------------|
| **NX**     | Segment `GNU_STACK` : flags `& W` absent → NX actif |
| **Canary** | Présence du symbole importé `__stack_chk_fail` |
| **RELRO**  | Segment `GNU_RELRO` présent (partial) + flag `DF_BIND_NOW` ou `DF_1_NOW` (full) |
| **PIE**    | `file_type == Header.FILE_TYPE.DYN` |
| **Fortify**| Symboles importés terminant par `_chk` (`__strcpy_chk`, etc.) |
| **RPATH**  | Tag dynamique `DT_RPATH` ou `DT_RUNPATH` présent |

Double source lief + pwntools : pwntools sert de vérification indépendante.

## Phase 3 — Analyse statique

### 3a. Fonctions dangereuses

Le catalogue comprend **14 fonctions dangereuses** réparties en catégories :

- **Dépassement de tampon sans borne** : `gets` (CRITICAL), `strcpy`, `strcat`, `sprintf`, `vsprintf` (HIGH), `scanf`, `sscanf` (MEDIUM)
- **Dépassement contrôlable** : `read`, `recv`, `memcpy`, `memmove` (MEDIUM — dépend des arguments)
- **Exécution de commande** : `system`, `popen` (CRITICAL)
- **Allocation de pile** : `alloca` (MEDIUM)

`printf` et `fprintf` ne figurent **pas** dans ce catalogue : ils déclencheraient des faux positifs sur tout binaire qui affiche du texte. La détection des chaînes de format est déléguée à l'analyse de teinte (phase 3c).

Pour chaque section exécutable du binaire, Capstone désassemble et recherche les instructions `CALL` dont l'opérande résout vers un stub PLT connu.

### 3b. Analyse de frame (disasm.py)

Pour chaque appel dangereux, vulnscan remonte dans la fonction appelante pour déterminer si le buffer cible a une taille fixe dans la frame et si la longueur de l'argument est connue au moment de la compilation.

L'état des registres est modélisé comme :

```
reg_state: dict[str, tuple["imm" | "rbp_rel" | "unknown", int]]
```

Les patterns suivis :
- `mov rdi, imm` → longueur immédiate connue
- `lea rdi, [rbp - N]` → buffer sur pile de taille N
- `lea rax, [rbp - N]; mov rdi, rax` → chaîne à travers registre intermédiaire
- `mov rdi, reg` → propagation de registre à registre

Trois cas déclenchent un finding :
1. Longueur de lecture > taille du buffer (dépassement certain)
2. Longueur non-constante (`rbp_rel`) — paramètre passé en argument
3. Longueur inconnue — valeur externe non traçable

### 3c. Taint intra-procédural (taint.py)

Suivi des flux depuis les sources d'entrée utilisateur vers les puits dangereux, à granularité registre + slot pile (relatif à RBP).

**Sources** : `gets`, `read`, `recv`, `fgets`, `scanf`, `getenv`, `getline`  
**Puits** : `strcpy`, `strcat`, `sprintf`, `system`, `memcpy`, etc.

Le moteur de taint maintient :
- `regs: set[str]` — registres actuellement taintés
- `stack: set[int]` — offsets RBP taintés (ex: `{-64}` pour `[rbp-0x40]`)
- `regs_val: dict[str, tuple[str, int]]` — valeur symbolique de chaque registre

Les MOV et LEA propagent le taint. Les registres caller-saved sont effacés après chaque CALL.

**Heuristique format string** : si l'argument de format de `printf`/`fprintf` est une adresse RBP-relative (buffer sur pile), un finding FORMAT_STRING est émis même sans taint inter-procédural.

## Phase 4 — Analyse dynamique

### 4a. Fuzzing (fuzzer.py)

Cinq stratégies de génération d'entrée :

| Stratégie | Description | Cible principale |
|-----------|-------------|-----------------|
| `size_escalation` | 1, 16, 64, 256 … 8192 octets de `A` | Détection générale |
| `cyclic` | Patterns De Bruijn pwntools 64–512 octets | Calcul d'offset RIP |
| `format_string` | `%s%s%n`, `%x.%x`, `%p%p` | Format string |
| `integer_boundary` | `count` autour de 0, 255, 65535, 4294967295 | Integer overflow |
| `integer_boundary_large` | count=4097 → 262 208 octets (overflow uint16) | Integer overflow réel |

Le fuzzer est déterministe avec un seed fixable. Il s'arrête après `max_crashes` crashs ou `max_iterations` itérations.

### 4b. Triage GDB (triage.py)

Pour chaque crash unique (par groupe de stratégie), vulnscan lance GDB en mode batch avec un script qui :

1. Charge le binaire et redirige stdin depuis le fichier d'entrée crashant
2. Capture les registres (`rip`, `rbp`, `rsp`) au moment du crash
3. Imprime 8 frames de backtrace
4. Lit les 8 octets au sommet de la pile (`x/2xg $rsp`) — adresse de retour corrompue
5. Invoke le plugin CERT `exploitable` si disponible

La valeur au RSP (pas le RIP courant qui pointe sur `ret`) est utilisée pour l'offset, car lors d'un stack BOF, l'instruction `ret` n'a pas encore dépilé la valeur corrompue.

L'offset vers RIP est calculé via `pwntools.cyclic_find(rsp_value & 0xFFFFFFFF)`.

## Phase 5 — Corrélation et sévérité

### Corrélation statique + dynamique

Lorsque l'analyse statique et l'analyse dynamique détectent la **même classe** de vulnérabilité, la confiance est élevée à `"both"`. Cela identifie les findings les plus fiables.

La déduplication s'applique uniquement aux findings **dynamiques** : plusieurs exécutions du fuzzer peuvent remonter le même bug ; seul le finding de meilleure confiance puis sévérité est conservé. Les findings statiques sont tous conservés car chaque analyseur (dangerous_funcs, disasm, taint) apporte une preuve distincte.

### Moteur de sévérité

```
score = base[vuln_class]
      + ajustement[exploitability]
      + bonus_offset
      - pénalité[protections]
      → clamp [1,5] → Severity
```

| Classe | Base |
|--------|------|
| STACK_BOF | 4 |
| HEAP_BOF, FORMAT_STRING, UAF | 3 |
| INTEGER_OVERFLOW, OFF_BY_ONE | 2 |
| UNKNOWN | 1 |

Ajustements : +2 EXPLOITABLE, +1 PROBABLY_EXPLOITABLE, −1 PROBABLY_NOT.  
Bonus : +1 si offset vers RIP calculé.  
Pénalités : −1 par protection active (canary, NX, PIE, full RELRO).

Si l'offset RIP est connu et la sévérité ≥ HIGH, le finding est promu à CRITICAL.
