# SQLi_XSS_tester

Scanner d'injections **SQL** et de **Cross-Site Scripting** en Python pur (aucune dépendance tierce), avec détection d'injections aveugles, contournement de WAF et génération de rapports.

> Outil de test pour audits de sécurité autorisés (pentest, CTF, labo personnel). Ne l'utilisez jamais contre une cible sans autorisation explicite.

## Fonctionnalités

- **Zéro dépendance externe** : uniquement la bibliothèque standard de Python 3.8+ (`urllib`, `html.parser`, `concurrent.futures`, `http.cookiejar`, `json`). Pas de `pip install` requis.
- **Crawling automatique** des formulaires et liens internes (même origine, profondeur bornée).
- **~90 payloads SQLi + ~73 payloads XSS** par point d'injection (arsenal complet par défaut, mode `--quick` disponible pour un arsenal réduit ~14/~12) :
  - SQLi : tautologies d'authentification, UNION-based (1 à 12 colonnes), error-based multi-SGBD (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), requêtes empilées, obfuscation anti-WAF (commentaires inline, casse, encodages, alternatives à l'espace), un peu de NoSQL en bonus.
  - XSS : balises/gestionnaires d'événements variés (`img`, `svg`, `video`, `details`, `marquee`, `iframe`, `object`…), échappement d'attribut, bypass sans espace/parenthèse, encodages multiples (entités HTML nommées/décimales/hex, URL simple/double, `\u`, découpage de balise), polyglottes.
  - SSTI : marqueurs `{{7*7}}`, `${7*7}`, `#{7*7}`, etc., avec une vraie vérification d'évaluation côté serveur (recherche du résultat calculé `49`, pas juste de la réflexion du marqueur).
- **SQLi error-based / UNION-based** via signatures d'erreurs SQL multi-SGBD.
- **SQLi aveugle (blind) booléenne** : compare la réponse de plusieurs paires de payloads `TRUE`/`FALSE` et signale une différence de longueur/statut significative, plutôt que de se fier à un simple mot-clé.
- **SQLi aveugle temporelle** : mesure le temps de réponse de payloads `SLEEP`/`pg_sleep`/`WAITFOR DELAY`/`DBMS_LOCK.SLEEP` (un par SGBD courant) par rapport à une requête de référence (baseline) pour détecter une injection sans retour visible.
- **Bypass d'authentification SQLi** sur les formulaires de login (détectés via la présence d'un champ `password`, pas juste ≥2 champs texte), avec comparaison à une réponse de référence (non authentifiée) plutôt qu'une simple absence de mot-clé d'erreur — évite les faux positifs classiques de ce genre de détection.
- **XSS réfléchie avec marqueur unique (canary)** : chaque test injecte un jeton aléatoire à côté du payload, pour attribuer correctement une réflexion à *ce* test précis plutôt qu'à un payload différent ayant réussi plus tôt dans le scan (important sur les pages à état, type mur de commentaires, qui réaffichent tout l'historique).
- **Détection de blocage WAF** et **contournement automatique** : encodage URL, casse alternée, injection de commentaires SQL (`/**/`), encodage d'entités HTML — rejoués automatiquement si le payload initial est bloqué.
- **Scan concurrent** (thread pool configurable), retries réseau (échec rapide sur cible injoignable), jitter optionnel.
- **Rapports** JSON et HTML autonomes.

## Utilisation

```bash
python3 SQLi_XSS_tester.py -u http://cible.exemple/ [options]
```

### Options principales

| Option | Description |
|---|---|
| `-u, --url` | URL cible (obligatoire) |
| `-t, --timeout` | Timeout par requête (défaut : 10s) |
| `-w, --workers` | Threads concurrents (défaut : 8) |
| `--delay` | Délai aléatoire (0..delay s) entre requêtes |
| `--max-pages` | Nombre max de pages crawlées (défaut : 20) |
| `--no-crawl` | Ne teste que l'URL donnée, sans crawling |
| `--no-forms` | Désactive le test des formulaires |
| `--no-blind` | Désactive les tests d'injection aveugle (plus rapide) |
| `-q, --quick` | Arsenal réduit (~14 SQLi / ~12 XSS) pour une passe de triage rapide |
| `--no-bypass` | Désactive les tentatives de contournement WAF |
| `--cookie` | En-tête `Cookie` brut |
| `-H, --header` | En-tête additionnel `"Nom: valeur"` (répétable) |
| `--proxy` | Proxy HTTP(S), ex. `http://127.0.0.1:8080` (Burp/ZAP) |
| `-o, --output` | Rapport JSON |
| `--html-report` | Rapport HTML |
| `-y, --yes` | Ignore la confirmation de périmètre |
| `-v, --verbose` | Affiche chaque test, pas seulement les résultats positifs |

### Exemple

```bash
python3 SQLi_XSS_tester.py -u http://127.0.0.1:8000/ --html-report rapport.html -y
```

### Arsenal complet vs. mode rapide

L'arsenal complet (défaut) vise la couverture maximale : chaque backend/WAF a ses propres angles morts, donc plus de variété de techniques et d'encodages augmente les chances de trouver la faille réelle. Sur une cible distante avec latence réseau et beaucoup de formulaires/paramètres découverts par le crawler, un scan complet peut prendre du temps — ajustez `--workers`, `--no-blind` (les tests aveugles sont les plus lents à cause du temporel), ou `--no-crawl` pour cibler directement un point d'injection connu. Pour une reconnaissance rapide sur de nombreuses cibles, utilisez `-q/--quick`.

## Sécurité et éthique

Au lancement, l'outil demande une confirmation explicite si la cible n'est pas `localhost`/`127.0.0.1`. `-y` permet de sauter cette confirmation en environnement automatisé.

## Limites connues

- La détection XSS repose sur la présence du payload (ou de sa forme décodée) dans le HTML brut ; elle ne simule pas un DOM/JS réel et peut manquer des XSS DOM-based pures (déclenchées uniquement côté client sans jamais transiter par le HTML serveur).
- La détection SQLi aveugle booléenne compare des tailles de réponse : une cible dont le contenu varie déjà naturellement (timestamp, contenu dynamique non lié à l'injection) peut produire un faux positif occasionnel — vérifiez manuellement les résultats `sqli-boolean-blind` avant de les considérer confirmés.
- Le contournement de WAF est heuristique et n'est pas garanti contre tous les WAF, en particulier les solutions commerciales à inspection contextuelle avancée.

## Développement et tests

Ce script a été développé et validé contre un labo web volontairement vulnérable maison (Python stdlib pur, 4 niveaux de protection croissante par catégorie de faille : aucune protection, filtre naïf, WAF avec angle mort, et implémentation sécurisée). Ce labo est un outil de développement séparé, non inclus dans ce dépôt.
