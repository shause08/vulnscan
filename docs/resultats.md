# Résultats — vulnscan

Résultats obtenus en scannant les six binaires du corpus de test. Tous les binaires sont compilés avec les protections désactivées (`-fno-stack-protector -z execstack -no-pie -Wl,-z,norelro -D_FORTIFY_SOURCE=0`).

## Environnement

- OS : Ubuntu 22.04 LTS, Linux 6.8.0 x86-64
- Compilateur : gcc 11.4
- Python : 3.10.12
- Dépendances : lief 1.0, capstone 5.0.3, pwntools 4.14, jinja2 3.1.6
- GDB : 12.1 + plugin CERT exploitable

## Protections détectées

| Binaire | NX | Canary | RELRO | PIE | Fortify | Résultat |
|---------|:--:|:------:|:-----:|:---:|:-------:|---------|
| stack\_bof\_vuln | ✗ | ✗ | no | ✗ | ✗ | Aucune protection |
| heap\_bof\_vuln | ✗ | ✗ | no | ✗ | ✗ | Aucune protection |
| format\_string\_vuln | ✗ | ✗ | no | ✗ | ✗ | Aucune protection |
| integer\_overflow\_vuln | ✗ | ✗ | no | ✗ | ✗ | Aucune protection |
| strcpy\_bof\_vuln | ✗ | ✗ | no | ✗ | ✗ | Aucune protection |
| heap\_overflow\_vuln | ✗ | ✗ | no | ✗ | ✗ | Aucune protection |

Tous les binaires `_vuln` ont les protections désactivées intentionnellement. vulnscan les détecte correctement dans chaque cas.

## Findings par binaire

### stack\_bof\_vuln — analyse statique seule

| Sévérité | Classe | Fonction | Confiance | Source |
|----------|--------|----------|-----------|--------|
| CRITICAL | stack-buffer-overflow | `vulnerable` | static | disasm (gets sans borne, frame 64 B) |
| HIGH | stack-buffer-overflow | `vulnerable` | static | dangerous_funcs (appel gets) |

### stack\_bof\_vuln — analyse complète (static + dynamic)

| Sévérité | Classe | Fonction | Confiance | Analyse |
|----------|--------|----------|-----------|---------|
| CRITICAL | stack-buffer-overflow | `vulnerable` | **both** | static |
| CRITICAL | stack-buffer-overflow | `<dynamic>` | **both** | dynamic (fuzzer crash) |
| HIGH | stack-buffer-overflow | `vulnerable` | **both** | static |

**Offset RIP calculé** : 72 octets (64 octets de buffer + 8 octets saved RBP).  
**Exploitability** : EXPLOITABLE (heuristique RIP = bytes ASCII cyclic).  
**Promotion CRITICAL** : l'offset vers RIP est connu → promotion automatique.

### heap\_bof\_vuln — analyse statique seule

| Sévérité | Classe | Fonction | Confiance | Source |
|----------|--------|----------|-----------|--------|
| MEDIUM | heap-buffer-overflow | `vulnerable` | static | disasm (read, longueur non constante) |
| MEDIUM | heap-buffer-overflow | `vulnerable` | static | dangerous_funcs (appel read) |

La vulnérabilité heap BOF est détectée en MEDIUM (longueur non-constante passée à `read`). Le fuzzer ne crashe pas le binaire non instrumenté (le heap overflow ne se manifeste qu'au prochain `malloc`/`free`) ; sans instrumentation dynamique, la détection reste statique uniquement.

### heap\_bof\_vuln — analyse complète

Identique à l'analyse statique seule : les findings restent `confidence=static` faute de crash dynamique détectable par le fuzzer.

### format\_string\_vuln — analyse statique seule

| Sévérité | Classe | Fonction | Confiance | Source |
|----------|--------|----------|-----------|--------|
| HIGH | format-string | `vulnerable` | static | taint (printf avec buffer RBP-rel) |

### format\_string\_vuln — analyse complète

| Sévérité | Classe | Fonction | Confiance | Analyse |
|----------|--------|----------|-----------|---------|
| CRITICAL | format-string | `<dynamic>` | **both** | dynamic (fuzzer crash %s%n) |
| HIGH | format-string | `vulnerable` | **both** | static |

Le fuzzer déclenche un crash SIGSEGV avec `%s%s%s%n` (accès mémoire arbitraire via `%n`).

### integer\_overflow\_vuln — analyse statique seule

| Sévérité | Classe | Fonction | Confiance | Source |
|----------|--------|----------|-----------|--------|
| MEDIUM | heap-buffer-overflow | `vulnerable` | static | disasm (memcpy, longueur non constante) |
| MEDIUM | heap-buffer-overflow | `vulnerable` | static | dangerous_funcs (appel memcpy) |

La vulnérabilité d'overflow entier elle-même n'est pas détectable statiquement (le calcul `uint16_t count * ELEM_SIZE` est syntaxiquement valide). vulnscan détecte la **conséquence** : `memcpy` avec longueur non-constante → HEAP_BOF MEDIUM. La stratégie `integer_boundary_large` (count=4097 → 262 208 octets copiés dans un buffer de 4 096 octets) peut déclencher un crash fuzzer sur le binaire non instrumenté selon la version de glibc.

### strcpy\_bof\_vuln — analyse statique seule

| Sévérité | Classe | Fonction | Confiance | Source |
|----------|--------|----------|-----------|--------|
| HIGH | stack-buffer-overflow | `vulnerable` | static | dangerous_funcs (appel strcpy) |
| HIGH | stack-buffer-overflow | `vulnerable` | static | taint (fgets → strcpy, buffer RBP-rel) |

`strcpy` copie `src` sans vérification de taille dans un buffer de 32 octets. dangerous_funcs et taint.py détectent tous deux la vulnérabilité via deux chemins distincts.

### strcpy\_bof\_vuln — analyse complète (static + dynamic)

| Sévérité | Classe | Fonction | Confiance | Analyse |
|----------|--------|----------|-----------|---------|
| CRITICAL | stack-buffer-overflow | `<dynamic>` | **both** | dynamic (crash sur 100 octets) |
| HIGH | stack-buffer-overflow | `vulnerable` | **both** | static (dangerous_funcs) |
| HIGH | stack-buffer-overflow | `vulnerable` | **both** | static (taint) |

**Crash confirmé** : 100 octets en entrée (buffer = 32 B) provoquent un SIGSEGV.  
**Offset RIP calculé** : 40 octets (32 B buffer + 8 B saved RBP).  
**Exploitability** : EXPLOITABLE (RIP écrasé par bytes cyclic ASCII).

### heap\_overflow\_vuln — analyse statique seule

| Sévérité | Classe | Fonction | Confiance | Source |
|----------|--------|----------|-----------|--------|
| MEDIUM | heap-buffer-overflow | `main` | static | dangerous_funcs (appel memcpy) |
| MEDIUM | heap-buffer-overflow | `main` | static | disasm (memcpy, longueur non constante) |

`memcpy(buf, staging, copy_len)` avec `copy_len` fourni par l'utilisateur et `buf = malloc(64)`. La longueur n'est pas bornée avant la copie.

### heap\_overflow\_vuln — analyse complète

| Sévérité | Classe | Fonction | Confiance | Analyse |
|----------|--------|----------|-----------|---------|
| CRITICAL | heap-buffer-overflow | `<dynamic>` | **both** | dynamic (crash sur copy_len > 64) |
| MEDIUM | heap-buffer-overflow | `main` | **both** | static (dangerous_funcs + disasm) |

Le fuzzer déclenche un crash en passant une valeur de copie supérieure à 64 (taille du buffer heap). Le heap overflow corrompt les métadonnées de l'allocateur et provoque un abort glibc ou un SIGSEGV.

## Récapitulatif global

| Binaire | Findings statiques | Classe principale | Dynamic |
|---------|:-----------------:|-------------------|:-------:|
| stack\_bof | 2 | STACK_BOF CRITICAL ✓ | CRITICAL + offset=72 |
| heap\_bof | 2 | HEAP_BOF MEDIUM ✓ | (pas de crash fuzzer) |
| format\_string | 1 | FORMAT_STRING HIGH ✓ | CRITICAL (%s%n crash) |
| integer\_overflow | 2 | HEAP_BOF MEDIUM ✓ (conséquence) | (variable selon glibc) |
| strcpy\_bof | 2 | STACK_BOF HIGH ✓ | CRITICAL + offset=40 |
| heap\_overflow | 2 | HEAP_BOF MEDIUM ✓ | CRITICAL (copy_len > 64) |

**Taux de détection** (au moins un finding pertinent par binaire) : **6/6 (100%)** — les quatre classes ciblées sont toutes détectées statiquement.

**Faux positifs éliminés** : `printf` et `fprintf` ont été retirés du catalogue de fonctions dangereuses. Les binaires qui affichent du texte avec un format littéral ne génèrent plus de faux positifs FORMAT_STRING. La détection des chaînes de format repose désormais exclusivement sur l'heuristique `rbp_rel` de taint.py, qui vérifie que l'argument de format est bien un buffer sur la frame courante.

## Performances

| Binaire | Statique seul | Static + Dynamic |
|---------|:-------------:|:----------------:|
| stack\_bof | ~0.4 s | ~35 s |
| heap\_bof | ~0.4 s | ~5 s |
| format\_string | ~0.4 s | ~10 s |
| integer\_overflow | ~0.4 s | ~5 s |
| strcpy\_bof | ~0.4 s | ~30 s |
| heap\_overflow | ~0.4 s | ~15 s |

Le temps dynamique est dominé par le fuzzer (150 itérations × timeout par exécution) et le triage GDB (~5 s par crash).
