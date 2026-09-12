# Limites — vulnscan

## Limites de l'analyse statique

### Pas d'analyse inter-procédurale

vulnscan effectue une analyse **intra-procédurale** uniquement. Il ne suit pas les données entre fonctions. Conséquences directes :

- Un taint qui traverse un appel de fonction (ex: `result = process(input); vuln(result)`) n'est pas propagé.
- La heuristique format-string compense partiellement pour `printf(buf)` où `buf` est un paramètre, mais reste imprecise.

### Pas de modélisation du tas

L'analyse ne suit pas les allocations et libérations de mémoire dynamique. Les vulnérabilités de type heap buffer overflow ne sont détectées que par inférence sur la taille des arguments (`memcpy` avec longueur non-constante).

### Portée limitée au code x86-64

- Seule l'architecture x86-64 est supportée pour l'analyse de frame et le taint. Les binaires ARM, AArch64, MIPS sont reconnus (parsing ELF) mais ne bénéficient pas du suivi de registres.
- Les binaires 32-bit (i386) ne bénéficient pas du taint (convention d'appel différente, paramètres sur la pile).

### Faux positifs sur les chaînes de format

`printf` et `fprintf` ne sont pas dans le catalogue de fonctions dangereuses pour éviter de signaler tout binaire qui affiche du texte. La détection repose sur l'heuristique `rbp_rel` (taint.py) : si l'argument de format est un buffer sur la frame courante, il est suspect. Cette heuristique génère des faux positifs quand :

- Une chaîne de format constante est stockée dans une variable locale puis passée à `printf` (pattern courant mais non dangereux).
- Le format argument est un buffer initialisé depuis `.rodata` mais copié sur la pile.

### Pas de désobfuscation

Les binaires packés (UPX), stripped, ou compilés avec LTO peuvent produire des résultats incomplets. Les sections PLT peuvent ne pas être reconnues si elles utilisent un format non standard.

### Analyse limitée aux sections exécutables connues

vulnscan scanne les sections marquées exécutables dans le header ELF. Le code injecté ou auto-modifiant n'est pas détecté.

## Limites de l'analyse dynamique

### Fuzzing sans feedback de couverture

Le fuzzer génère des entrées de façon déterministe sans instrument de couverture (pas de coverage-guided fuzzing à la AFL/libFuzzer). Il peut manquer des chemins d'exécution qui nécessitent des entrées structurées (parseurs, protocoles) ou des conditions complexes (`if (input == 0xdeadbeef)`).

### Dépendance à l'entrée standard (stdin)

La majorité des stratégies de fuzzing ciblent stdin. Les vulnérabilités déclenchées par :
- Des arguments de ligne de commande (`argv`)
- Des variables d'environnement
- Des fichiers de configuration
- Des sockets réseau

... nécessitent une instrumentation supplémentaire hors scope de ce projet. Exception partielle : la stratégie `integer_boundary` passe `argv_extra` pour les binaires qui attendent un count en argument.


### Heap overflow sans crash immédiat

Un heap overflow dans glibc peut ne pas provoquer de SIGSEGV immédiat : le bloc de métadonnées corrompu n'est détecté qu'au prochain `malloc`/`free`. Le fuzzer peut donc ne pas détecter le crash pour les binaires non instrumentés.

### Timeout et couverture

Avec `--timeout 30`, le fuzzer a ~5 itérations effectives par seconde, soit ~150 itérations au total. Les binaires complexes (parseurs, serveurs) nécessitent des timeouts plus élevés.

## Limites du triage

### GDB batch pas disponible partout

Le mode triage GDB requiert GDB ≥ 7.0 installé sur l'hôte. Sans GDB, le triage repasse en mode fallback (signal seul, pas de RIP, pas d'exploitability).

### Plugin CERT exploitable optionnel

`exploitable.py` n'est pas dans les dépôts officiels Ubuntu 22.04. Sans lui, l'exploitability est estimée heuristiquement (RIP dans la plage ASCII = PROBABLY_EXPLOITABLE), avec moins de précision.

### Offset valide pour stack BOF simple uniquement

`cyclic_find` pour calculer l'offset vers RIP fonctionne uniquement si :
- Le pattern cyclic atteint directement l'adresse de retour sur la pile
- Le binaire n'utilise pas de stack cookie (canary)
- Le binaire n'est pas PIE (position-independent : les adresses varient à chaque run)

Pour les heap overflow ou format string, l'offset vers une adresse de contrôle n'est pas calculé.

## Limites architecturales générales

### Pas de détection de race conditions

Les vulnérabilités TOCTOU (time-of-check to time-of-use) et les data races nécessitent une analyse multi-thread hors scope.

### Pas d'analyse de flux de contrôle globale (CFG)

vulnscan ne construit pas de graphe de flux de contrôle inter-procédural. Des chemins d'exécution inatteignables peuvent générer des faux positifs (ex: une branche morte contenant un appel à `gets`).

### Pas de détection de vulnérabilités cryptographiques

Utilisation de fonctions faibles (`md5`, `rand`, `srand`), comparaisons non-constant-time, etc. : hors périmètre.

### Précision du calcul de taille de buffer

La taille du buffer est inférée depuis l'offset RBP de l'instruction LEA. Cette mesure est parfois surestimée si d'autres variables locales précèdent le buffer sur la frame. Des faux négatifs sont possibles si la taille n'est pas statiquement déterminable (buffer alloué via `alloca`).

## Conclusion

vulnscan est un outil à vocation académique et pédagogique. Les limitations listées ci-dessus font l'objet de recherches actives dans le domaine de l'analyse de programme (analyse inter-procédurale, abstract interpretation, symbolic execution) et des outils industriels comme CodeQL, Infer, AFLplusplus ou SAGE les adressent partiellement. vulnscan vise à illustrer les principes fondamentaux plutôt qu'à rivaliser avec ces outils en termes de précision.
