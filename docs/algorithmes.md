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

## 6. Déduplication des findings dynamiques

Plusieurs exécutions du fuzzer sur des entrées différentes peuvent produire le même finding. La déduplication ne s'applique qu'aux findings **dynamiques** (pas statiques, qui apportent chacun une preuve distincte). La clé est `(vuln_class, function)` ; le meilleur finding est conservé selon l'ordre `confidence` puis `severity`.
