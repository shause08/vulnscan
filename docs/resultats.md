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

### stack\_bof\_vuln — analyse statique

| Sévérité | Classe | Fonction | Confiance | Source |
|----------|--------|----------|-----------|--------|
| CRITICAL | stack-buffer-overflow | `vulnerable` | static | disasm (gets sans borne) |
| HIGH | stack-buffer-overflow | `vulnerable` | static | taint (gets → stack) |
| HIGH | format-string | `vulnerable` | static | taint (printf format RBP-rel) |

### stack\_bof\_vuln — analyse complète (static + dynamic)

| Sévérité | Classe | Fonction | Confiance |
|----------|--------|----------|-----------|
| CRITICAL | stack-buffer-overflow | `vulnerable` | **both** |
| CRITICAL | stack-buffer-overflow | `<dynamic>` | **both** |
| HIGH | stack-buffer-overflow | `vulnerable` | **both** |
| HIGH | stack-buffer-overflow | `printf_common` | **both** |
| HIGH | format-string | `vulnerable` | static |

**Offset RIP calculé** : 72 octets (64 octets de buffer + 8 octets saved RBP).  
**Exploitability** : EXPLOITABLE (GDB plugin CERT + heuristique RIP = bytes ASCII cyclic).  
**Promotion CRITICAL** : l'offset vers RIP est connu → promotion automatique.

### heap\_bof\_vuln — analyse statique

| Sévérité | Classe | Fonction | Confiance |
|----------|--------|----------|-----------|
| HIGH | format-string | `main` | static |
| HIGH | format-string | `vulnerable` | static |
| MEDIUM | heap-buffer-overflow | `vulnerable` | static |
| MEDIUM | heap-buffer-overflow | `vulnerable` | static |

La vulnérabilité heap BOF est détectée en MEDIUM (longueur non-constante passée à `read`). L'absence de crash immédiat dans glibc sans ASan limite la détection dynamique ; le build ASan `heap_bof_asan` détecte un `heap-buffer-overflow` HIGH avec argv `300`.

### format\_string\_vuln — analyse statique

| Sévérité | Classe | Fonction | Confiance |
|----------|--------|----------|-----------|
| HIGH | format-string | `vulnerable` | static |
| HIGH | format-string | `main` | static |
| HIGH | format-string | `vulnerable` | static |

Trois findings distincts correspondent à trois appels `printf` avec argument contrôlable. Le fuzzer déclenche un crash SIGSEGV avec `%s%s%s%n` (accès mémoire arbitraire via `%n`).

### integer\_overflow\_vuln — analyse statique

| Sévérité | Classe | Fonction | Confiance |
|----------|--------|----------|-----------|
| HIGH | format-string | `main` | static |
| HIGH | format-string | `vulnerable` | static |
| MEDIUM | heap-buffer-overflow | `vulnerable` | static |
| MEDIUM | heap-buffer-overflow | `vulnerable` | static |

La vulnérabilité d'overflow entier elle-même n'est pas détectable statiquement (le calcul `uint16_t count * ELEM_SIZE` est syntaxiquement valide). vulnscan détecte la conséquence : `memcpy` avec longueur non-constante → HEAP_BOF MEDIUM. Dynamiquement, la stratégie `integer_boundary_large` (count=4097, stdin=262 208 octets) déclenche le crash ASan.

### uaf\_vuln — analyse statique

| Sévérité | Classe | Fonction | Confiance |
|----------|--------|----------|-----------|
| HIGH | format-string | `default_greet` | static |
| HIGH | format-string | `admin_greet` | static |

La vulnérabilité UAF elle-même (free() suivi d'un accès via pointeur dangling) n'est pas détectable par analyse statique intra-procédurale. vulnscan détecte les appels `printf` avec format potentiellement contrôlable dans les deux fonctions. L'ASan build `uaf_asan` détecte `heap-use-after-free` HIGH avec `func=main`.

### off\_by\_one\_vuln — analyse statique

| Sévérité | Classe | Fonction | Confiance |
|----------|--------|----------|-----------|
| HIGH | format-string | `vulnerable` | static |
| HIGH | format-string | `main` | static |

La vulnérabilité off-by-one (boucle `for i in range(BUF_SIZE+1)`) déborde d'un octet. Le build ASan `off_by_one_asan` détecte `stack-buffer-overflow` HIGH en `vulnerable()` avec un input de 64 octets.

## Récapitulatif global

| Binaire | Findings statiques | Classe principale détectée | Dynamique |
|---------|:-----------------:|--------------------------|:---------:|
| stack\_bof | 3 | STACK_BOF ✓ | CRITICAL + offset=72 |
| heap\_bof | 4 | HEAP_BOF ✓ (MEDIUM) | ASan: HEAP_BOF HIGH |
| format\_string | 3 | FORMAT_STRING ✓ | Crash %s%n |
| integer\_overflow | 4 | HEAP_BOF ✓ (conséquence) | ASan: HEAP_BOF HIGH |
| uaf | 2 | FORMAT_STRING (partiel) | ASan: USE_AFTER_FREE HIGH |
| off\_by\_one | 2 | FORMAT_STRING (partiel) | ASan: STACK_BOF HIGH |

**Taux de détection** (au moins un finding pertinent par binaire) : **6/6 (100%)** avec la combinaison statique + dynamique.

**Faux positifs observés** : les appels `printf(fmt_str, ...)` avec format littéral constant sont parfois signalés comme format-string potentiels si la chaîne de format est chargée depuis une variable locale (pas directement depuis `.rodata`). Ce comportement est attendu pour une analyse intra-procédurale conservative.

## Performances

| Binaire | Statique seul | Static + Dynamic |
|---------|:-------------:|:----------------:|
| stack\_bof | 0.38 s | ~35 s |
| heap\_bof | 0.41 s | ~35 s |
| format\_string | 0.35 s | ~35 s |
| integer\_overflow | 0.40 s | ~40 s |
| uaf | 0.33 s | ~30 s |
| off\_by\_one | 0.36 s | ~30 s |

Le temps dynamique est dominé par le fuzzer (150 itérations × timeout par exécution) et le triage GDB (~5 s par crash).
