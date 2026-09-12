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
| uaf\_vuln | ✗ | ✗ | no | ✗ | ✗ | Aucune protection |
| off\_by\_one\_vuln | ✗ | ✗ | no | ✗ | ✗ | Aucune protection |

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

### uaf\_vuln — analyse statique seule

Aucun finding statique. La vulnérabilité UAF (free() suivi d'un accès via pointeur dangling) n'est pas détectable par analyse statique intra-procédurale : le free et l'accès sont dans des chemins d'exécution distincts.

### uaf\_vuln — analyse complète

Aucun finding dynamique. Le fuzzer ne crashe pas le binaire non instrumenté car le chunk libéré est immédiatement recyclé par `malloc` et le pointeur dangling finit par appeler une fonction valide — pas de SIGSEGV. La vulnérabilité UAF n'est pas détectable sans instrumentation mémoire.

### off\_by\_one\_vuln — analyse statique seule

Aucun finding statique. L'off-by-one (boucle `for i in range(BUF_SIZE+1)`) n'est pas détectable sans modélisation des bornes de boucle.

### off\_by\_one\_vuln — analyse complète

Aucun finding dynamique. La boucle écrit un octet nul en dehors du buffer, qui écrase l'octet de poids faible du saved RBP. Ce dépassement ne provoque pas de crash dans le binaire non instrumenté (le programme retourne à une adresse légèrement différente mais souvent valide). La vulnérabilité off-by-one n'est pas détectable sans instrumentation mémoire.

## Récapitulatif global

| Binaire | Findings statiques | Classe principale | Dynamic |
|---------|:-----------------:|-------------------|:-------:|
| stack\_bof | 2 | STACK_BOF CRITICAL ✓ | CRITICAL + offset=72 |
| heap\_bof | 2 | HEAP_BOF MEDIUM ✓ | (pas de crash fuzzer) |
| format\_string | 1 | FORMAT_STRING HIGH ✓ | CRITICAL (%s%n crash) |
| integer\_overflow | 2 | HEAP_BOF MEDIUM ✓ (conséquence) | (variable selon glibc) |
| uaf | 0 | — | (non détectable sans instrumentation) |
| off\_by\_one | 0 | — | (non détectable sans instrumentation) |

**Taux de détection** (au moins un finding pertinent par binaire) : **4/6 (67%)** en statique+dynamique seul ; `uaf` et `off_by_one` requièrent une instrumentation mémoire (ex. Valgrind) pour être détectés dynamiquement.

**Faux positifs éliminés** : `printf` et `fprintf` ont été retirés du catalogue de fonctions dangereuses. Les binaires qui affichent du texte avec un format littéral ne génèrent plus de faux positifs FORMAT_STRING. La détection des chaînes de format repose désormais exclusivement sur l'heuristique `rbp_rel` de taint.py, qui vérifie que l'argument de format est bien un buffer sur la frame courante.

## Performances

| Binaire | Statique seul | Static + Dynamic |
|---------|:-------------:|:----------------:|
| stack\_bof | ~0.4 s | ~35 s |
| heap\_bof | ~0.4 s | ~5 s |
| format\_string | ~0.4 s | ~10 s |
| integer\_overflow | ~0.4 s | ~5 s |
| uaf | ~0.4 s | ~5 s |
| off\_by\_one | ~0.4 s | ~5 s |

Le temps dynamique est dominé par le fuzzer (150 itérations × timeout par exécution) et le triage GDB (~5 s par crash). Les binaires sans crash fuzzer (uaf, off_by_one) sont plus rapides car le fuzzer termine sans triage GDB.
