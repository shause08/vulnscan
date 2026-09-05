# Algorithmes — vulnscan

Détail des algorithmes non triviaux implémentés dans vulnscan.

## 1. Résolution de la PLT en présence d'IBT/CET

**Problème** : pwntools `ELF.plt` renvoie un dictionnaire vide pour les binaires compilés avec `-fcf-protection` (gcc ≥ 9), car la PLT classique est remplacée par `.plt.sec`.

**Solution** : désassemblage direct des sections PLT dans l'ordre de priorité :

```
.plt.sec  (IBT stubs — prioritaire)
.plt.got  (GOT-only PLT)
.plt      (PLT classique)
```

Pour chaque instruction dans `.plt.sec`, l'algorithme cherche un `jmp` ou `bnd jmp` à opérande mémoire de la forme `[rip + N]` :

```python
# adresse de la prochaine instruction après le JMP (RIP au moment de l'exécution)
rip_next = insn.address + insn.size
got_addr = rip_next + displacement

# résolution GOT → nom de symbole via .rela.plt
for reloc in binary.relocations:
    if reloc.address == got_addr and reloc.has_symbol:
        plt_map[stub_addr] = reloc.symbol.name
```

**Complexité** : O(|PLT| × |relocations|) — linéaire en pratique car les deux tables sont petites.

## 2. Analyse de frame intra-procédurale

**Objectif** : déterminer si l'appel `read(fd, buf, n)` peut déborder `buf`.

L'algorithme simule l'exécution des instructions précédant le CALL en maintenant un état symbolique des registres.

### Structure d'état

```python
@dataclass
class RegState:
    reg_state: dict[str, tuple[str, int]]
    # clé   : nom du registre (rdi, rsi, rdx, rax, …)
    # valeur: ("imm", v)      → constante immédiate v
    #         ("rbp_rel", v)  → adresse [rbp + v] (v négatif pour la pile)
    #         ("unknown", 0)  → valeur inconnue
```

### Règles de transfert

| Instruction | Effet |
|-------------|-------|
| `mov reg, imm` | `reg ← ("imm", imm)` |
| `mov reg1, reg2` | `reg1 ← state[reg2]` |
| `lea reg, [rbp + d]` | `reg ← ("rbp_rel", d)` |
| `mov reg, [rbp + d]` | `reg ← ("unknown", 0)` (valeur mémoire) |
| `mov [rbp + d], reg` | mise à jour slot pile si reg connu |
| `CALL` | registres caller-saved effacés : rax, rcx, rdx, rsi, rdi, r8–r11 |

### Inférence de la taille du buffer

Quand le premier argument (RDI pour un appel `read(fd, buf, n)`) est de type `rbp_rel` :

```
buf_size = |rbp_rel_offset|    (taille jusqu'au sommet du frame précédent)
```

La taille réelle est souvent plus petite (la frame contient d'autres variables), mais c'est une borne supérieure conservative.

### Décision de finding

```
if len_type == "imm" and len_val > buf_size:
    → STACK_BOF certain (HIGH)
elif len_type in ("rbp_rel", "unknown"):
    → longueur non constante, potentiellement contrôlable (MEDIUM)
```

## 3. Taint tracking intra-procédural

**Abstraction** : lattice à deux éléments `{tainted, untainted}` sur chaque registre et slot pile.

### Propagation

```
Sources → taint initial
  gets(buf)         : buf (rdi → slot rbp_rel) ← tainted
  read(fd, buf, n)  : buf (rsi → slot rbp_rel) ← tainted
  recv, fgets, scanf, getenv, getline : argument buffer ← tainted

Propagation (over-approximation)
  MOV dst, src      : tainted(dst) |= tainted(src)
  LEA dst, [rbp+d]  : tainted(dst) |= tainted(slot d)
  MOV [rbp+d], src  : tainted(slot d) |= tainted(src)
  CALL              : caller-saved regs cleared (conservative)

Puits → émission de finding
  strcpy(dst, src)  : src (rsi) tainted → STACK_BOF
  system(cmd)       : cmd (rdi) tainted → CRITICAL
  memcpy(d,s,n)     : src (rsi) tainted → heap/stack BOF
```

### Heuristique format string (sans taint inter-procédural)

`printf` et `fprintf` ne sont pas dans le catalogue `dangerous_funcs` (trop de faux positifs : tout binaire qui affiche du texte avec un format littéral serait signalé). La détection repose sur une heuristique intra-procédurale : si l'argument de format de `printf`/`fprintf` est une adresse RBP-relative (buffer alloué sur la frame courante), le buffer provient forcément de données locales et est suspect.

```python
if func_name in ("printf", "fprintf"):
    fmt_reg = "rdi" if func_name == "printf" else "rsi"
    val_type, val = regs_val.get(fmt_reg, ("unknown", 0))
    if val_type == "rbp_rel":
        emit(FORMAT_STRING, HIGH)
```

Cette heuristique capte le pattern `char buf[N]; fgets(buf, N, stdin); printf(buf);` sans analyse inter-procédurale, au prix de quelques faux positifs sur les buffers initialisés avec des formats constants.

## 4. Calcul de l'offset vers RIP (cyclic_find)

### Génération de pattern De Bruijn

pwntools `cyclic(N)` génère une séquence sur un alphabet de 26 lettres minuscules où tout sous-mot de longueur 4 (ou 8 en mode 64-bit) est unique. Propriété : étant donné n'importe quelle sous-séquence de 4 octets, `cyclic_find(subseq)` retourne son offset dans le pattern en temps O(1).

### Extraction de l'adresse corrompue

Lors d'un crash après stack BOF, la séquence d'exécution est :

```
1. vulnerable() : gets(buf) écrit le pattern au-delà de buf
2. La valeur à [rbp+8] (adresse de retour sauvegardée) est remplacée par pattern[72:80]
3. `leave` : rsp ← rbp + 8
4. `ret`   : rip ← *rsp  (pointe maintenant sur pattern[72:80])
            rsp += 8
5. SIGSEGV car rip contient une adresse non-mappée
```

Au moment du SIGSEGV, GDB voit :
- `$rip = 0x4011a4` (adresse de `ret` — valeur *avant* le dépilage)
- `$rsp` pointe sur `pattern[72:80]` (la valeur qui *sera* chargée dans RIP)

vulnscan lit `x/2xg $rsp` pour obtenir la valeur corrompue, puis :

```python
rip_value = stack_top_value          # ex: 0x6161617461616173
offset = cyclic_find(rip_value & 0xFFFFFFFF)  # → 72
```

### Pourquoi masquer à 32 bits ?

`cyclic_find` avec un entier cherche un pattern de 4 octets. Les 4 octets de poids faible de `rip_value` correspondent à `pattern[72:76]`, suffisants pour identifier l'offset unique.

## 5. Moteur de sévérité

### Formule

```
score_base = {STACK_BOF:4, HEAP_BOF:3, FORMAT_STRING:3,
              USE_AFTER_FREE:3, INTEGER_OVERFLOW:2, OFF_BY_ONE:2, UNKNOWN:1}

score += exploit_bonus
  EXPLOITABLE          → +2
  PROBABLY_EXPLOITABLE → +1
  PROBABLY_NOT         → -1

score += 1  si offset_to_rip connu

score -= 1  par protection active : canary, NX, PIE, relro=="full"

score = clamp(score, 1, 5)

Severity = [INFO, LOW, MEDIUM, HIGH, CRITICAL][score - 1]
```

### Post-traitement pipeline

Si `offset_to_rip is not None` et `sev in {HIGH, MEDIUM}` → promouvoir à CRITICAL.

Rationale : un offset vers RIP connu signifie que l'attaquant peut construire un exploit précis (ret2libc, ROP). L'existence de cet offset rend la vulnérabilité directement exploitable indépendamment des protections résiduelles.

## 6. Parsing du rapport ASan

### Format ASan typique

```
==PID==ERROR: AddressSanitizer: <type> on address 0x... at pc 0x...
<ACCESS_OP> of size N at 0x...
    #0 0xaddr in func_name file.c:line
    #1 ...
freed by thread T0 here:
    #0 0xaddr in free ...
    #1 0xaddr in main file.c:line
previously allocated by thread T0 here:
    ...
SUMMARY: AddressSanitizer: <type>
```

### Découpe en sections

ASan produit plusieurs sections de backtrace pour un même évènement (accès fautif, libération, allocation). Le parseur divise le bloc brut avant le premier marqueur secondaire (`freed by thread`, `previously allocated by`, `SUMMARY:`, `Shadow bytes`, `Address 0x`) pour ne conserver que la **section primaire** (l'accès qui a déclenché l'erreur).

```python
sec_match = _RE_SECONDARY.search(self.raw)
primary_text = self.raw[:sec_match.start()] if sec_match else self.raw
self.frames = self._extract_frames(primary_text)
```

Les frames de la section `freed by` sont capturées séparément dans `freed_frames` pour les erreurs UAF/double-free, afin d'afficher le site du `free()` dans la preuve.

### Tri et filtrage des frames

Les frames sont triées par index après extraction (garantit l'ordre #0, #1, #2… même si la regex les trouve dans un ordre quelconque).

Les frames appartenant aux runtimes internes sont ignorées :

```python
_RUNTIME_PREFIXES = (
    "__interceptor_", "__sanitizer_", "__sanitizer::",
    "__asan_", "_asan_", "asan_",
    "__libc_", "__GI_", "libc_",
)
_RUNTIME_EXACT = {"??", "<unknown>", "_start", "__start",
                   "__libc_start_main", "__libc_start_call_main"}
```

Note : le namespace C++ `__sanitizer::` (double deux-points) est distinct du préfixe `__sanitizer_` (underscore), d'où l'entrée séparée.

### Cas particulier : DEADLYSIGNAL (nested bug)

`gets()` peut écrire au-delà de la shadow memory d'ASan elle-même, causant un deuxième crash à l'intérieur du gestionnaire d'erreur ASan :

```
==PID==ERROR: AddressSanitizer: stack-buffer-overflow ...
AddressSanitizer: nested bug in the same thread, aborting.
SUMMARY: AddressSanitizer: DEADLYSIGNAL
```

L'algorithme de parsing détecte DEADLYSIGNAL comme suffixe et re-scanne le bloc entier depuis le début pour retrouver l'`ERROR:` initial :

```python
if not self.error_type and "DEADLYSIGNAL" in self.raw:
    m = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", self.raw)
    if m:
        self.error_type = m.group(1).lower()
```

### Colonne localisation

Le champ `location` du Finding est rempli avec l'adresse hexadécimale ASan (`0x...`) en priorité. La référence source (`src/file.c:line`), issue des symboles DWARF embarqués dans le binaire compilé avec `-g`, est conservée dans le texte de preuve mais n'est pas affichée dans la colonne adresse pour éviter toute confusion avec une adresse binaire.

## 7. Entrées ASan de référence (baseline)

### Problème

Certaines vulnérabilités (UAF, off-by-one sur RBP, corruptions silencieuses) ne provoquent pas de crash dans le binaire non instrumenté, donc le fuzzer ne génère aucune entrée crashante et ASan n'est jamais invoqué.

### Solution

Un ensemble d'entrées **systématiques** est toujours fourni au binaire ASan, indépendamment des résultats du fuzzer :

```python
_ASAN_BASELINE: list[bytes] = [
    b"",              # entrée vide — détecte les bugs sans entrée (UAF à l'init)
    b"A" * 63 + b"\n",
    b"A" * 64 + b"\n",   # taille exacte du buffer typique
    b"A" * 65 + b"\n",   # off-by-one
    b"A" * 127 + b"\n",
    b"A" * 128 + b"\n",
    b"A" * 129 + b"\n",
]
```

Les tailles 63/64/65 et 127/128/129 encadrent les puissances de deux courantes pour attraper les off-by-one. L'entrée vide déclenche les bugs qui se produisent dès le démarrage (ex. : UAF dont le malloc initial recycle immédiatement le bloc libéré).

### Déduplication des findings dynamiques

Plusieurs exécutions ASan sur des entrées différentes peuvent produire le même finding. La déduplication ne s'applique qu'aux findings **dynamiques** (pas statiques, qui apportent chacun une preuve distincte). La clé est `(vuln_class, function)` ; le meilleur finding est conservé selon l'ordre `confidence` puis `severity`.

La confiance `"both"` au niveau dynamique signifie que plusieurs exécutions ASan/fuzzer ont détecté indépendamment le même bug — distinct du `"both"` statique+dynamique calculé par `_merge_findings`.
