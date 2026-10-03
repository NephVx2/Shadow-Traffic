# Shadow-Traffic

🇬🇧 [English version](README.md)

**Voit ce qui sort réellement de la machine, en ce moment — y compris ce que vos outils basés sur le DNS ne peuvent pas voir.**

`Shadow-Traffic` observe les connexions TCP sortantes réelles pendant une fenêtre de temps fixe (2 minutes par défaut), lit le nom d'hôte de destination directement sur le fil quand c'est possible (via le champ SNI du ClientHello TLS, grâce à un parseur de paquets bas niveau écrit à la main — aucun outil de capture externe requis en dehors de `pktmon`, natif à Windows), et croise chaque endpoint avec les listes de domaines connus de [Block-Telemetry](https://github.com/NephVx2/Block-Telemetry). Résultat : une image en direct de ce à quoi votre machine parle réellement, quel processus en est responsable, et si l'un de ces échanges concerne un domaine censé être bloqué mais qui passe quand même.

> **À ne pas confondre avec [Check-Network](https://github.com/NephVx2/Check-Network)** — voir [Shadow-Traffic vs. Check-Network](#shadow-traffic-vs-check-network) plus bas si vous hésitez entre les deux.

> **Note :** l'intégralité de l'interface (console, paramètres, rapport HTML) est en anglais. Ce README est en français, mais tout ce que vous verrez à l'écran en lançant le script sera en anglais — le script fonctionne de façon identique sur une machine Windows française ou anglaise.

---

## Sommaire

- [Pourquoi ce script existe](#pourquoi-ce-script-existe)
- [Captures d'écran](#captures-décran)
- [Shadow-Traffic vs. Check-Network](#shadow-traffic-vs-check-network)
- [Ce qu'il fait](#ce-quil-fait)
- [Ce qu'il ne fait *pas*](#ce-quil-ne-fait-pas)
- [Prérequis](#prérequis)
- [Premier lancement (étape par étape)](#premier-lancement-étape-par-étape)
- [Démarrage rapide](#démarrage-rapide)
- [Raccourci bureau](#raccourci-bureau)
- [Paramètres](#paramètres)
- [Lire la sortie console](#lire-la-sortie-console)
- [Comment fonctionne la classification](#comment-fonctionne-la-classification)
- [Le rapport HTML](#le-rapport-html)
- [Rapports et fichiers](#rapports-et-fichiers)
- [Intégration avec Block-Telemetry](#intégration-avec-block-telemetry)
- [Confidentialité](#confidentialité)
- [Self-test](#self-test)
- [Dépannage](#dépannage)

---

## Pourquoi ce script existe

[Block-Telemetry](https://github.com/NephVx2/Block-Telemetry) bloque des domaines au niveau DNS, en les redirigeant vers nulle part (0.0.0.0) dans le fichier hosts. C'est efficace, mais avec un angle mort précis : ça ne peut vous dire que ce qui a été *demandé par son nom*. Une adresse IP codée en dur, un résolveur DNS intégré directement dans une application plutôt que dans l'OS (DNS-over-HTTPS dans NVIDIA App, par exemple), ou un domaine que personne n'a encore pensé à ajouter à la liste de blocage — rien de tout ça n'apparaît dans un outil basé sur le fichier hosts, puisque la requête DNS qui aurait déclenché le blocage n'a tout simplement jamais lieu.

`Shadow-Traffic` pose une question différente de « ce domaine est-il sur la liste ? ». Il demande **« à quoi mon ordinateur est-il réellement en train de se connecter, sur le fil, en ce moment ? »** — en échantillonnant les connexions TCP réelles et, quand c'est possible, en lisant le vrai nom de destination directement dans la poignée de main TLS, que la requête DNS correspondante ait été loggée ou non. C'est la différence entre vérifier une liste d'invités et se tenir directement à la porte.

## Captures d'écran

<p align="center">
  <img src="https://raw.githubusercontent.com/NephVx2/Shadow-Traffic/main/screenshots/01-shadow-traffic-preview.png" width="49%">
  <img src="https://raw.githubusercontent.com/NephVx2/Shadow-Traffic/main/screenshots/02-html-preview.png" width="49%">
</p>

Davantage dans [`screenshots/`](https://github.com/NephVx2/Shadow-Traffic/tree/main/screenshots).

---

## Shadow-Traffic vs. Check-Network

Les deux scripts examinent l'activité réseau, les deux produisent un rapport HTML/JSON/CSV, et les deux font partie de la même suite « maintenance Windows 11 » — il est donc facile de les confondre. Ils répondent pourtant à deux questions complètement différentes :

| | **Check-Network** | **Shadow-Traffic** |
|---|---|---|
| **Question à laquelle il répond** | « Ma *connexion* réseau est-elle saine et sécurisée ? » | « À quoi ma machine *parle*-t-elle, réellement, en ce moment ? » |
| **Nature** | Scan de santé/sécurité ponctuel | Capture de trafic en direct sur une fenêtre de temps |
| **Durée** | Quelques secondes à ~1 minute (essentiellement des vérifications instantanées + un test de débit optionnel) | Une fenêtre configurable, 120 secondes par défaut (`-DurationSeconds`) |
| **Ce qu'il regarde** | Adaptateurs, latence de la passerelle, serveurs DNS, config DoH/NextDNS, historique Wi-Fi, certificats racine, débit, portail captif, fuites IPv6/DNS | Les connexions TCP réelles ouvertes par vos processus, plus (en option) le nom d'hôte SNI TLS lu directement dans les paquets |
| **Type de résultat** | Un score de 0 à 100 par catégorie (Connectivity / Security / DNS) | Une liste d'endpoints classés : Known / Unclassified / **ANOMALY** |
| **Droits admin requis ?** | Oui, toujours | Seulement pour `-CaptureSNI` (capture de paquets via `pktmon`) ; l'audit TCP de base n'en a pas besoin |
| **Usage typique** | « Est-ce que quelque chose ne va pas avec mon réseau ou ma config DNS ? » | « À qui ce processus envoie-t-il réellement des données, et est-ce que ça concerne quelque chose que je voulais bloquer ? » |

**En bref :** lancez **Check-Network** pour vérifier la santé de votre connexion. Lancez **Shadow-Traffic** pour voir ce qui transite réellement sur le fil et repérer ce qui passerait entre les mailles de Block-Telemetry.

## Ce qu'il fait

- Échantillonne les connexions TCP sortantes réelles (`Get-NetTCPConnection`) toutes les 5 secondes pendant la fenêtre d'observation, en notant l'IP de destination, le port, le processus propriétaire, et le nombre de fois où chaque endpoint a été vu.
- En option (`-CaptureSNI`), lance une capture de paquets en direct via `pktmon` en parallèle de cette même fenêtre, et parse lui-même les octets bruts Ethernet/IP/TCP/TLS pour extraire le **SNI** (Server Name Indication) — le vrai nom d'hôte demandé au serveur de destination pendant la poignée de main TLS. Aucun outil externe (Wireshark, tshark...) n'est nécessaire.
- Réassemble un ClientHello coupé en deux segments TCP sur le fil (best-effort, segments contigus uniquement).
- Compte le trafic UDP:443 (QUIC/HTTP3) séparément, pour qu'il reste visible dans les totaux même si son contenu n'est pas décodé.
- Résout un nom DNS inverse (PTR) pour les endpoints sans SNI capturé, et se rabat sur une recherche d'ASN/organisation (via le service DNS public de Team Cymru, sans clé API) quand même ça échoue — ainsi « 204.79.197.203 » devient « Microsoft Corporation (AS8075) » plutôt que de rester un numéro opaque.
- Croise chaque endpoint nommé avec les listes de domaines bloqués et en liste blanche de [Block-Telemetry](https://github.com/NephVx2/Block-Telemetry), et marque comme **ANOMALY** tout ce qui correspond à un domaine **bloqué** (il est passé malgré tout — un contournement).
- Conserve une baseline persistante (`Baseline_Shadow-Traffic.json`) entre les lancements, pour pouvoir signaler les endpoints **jamais vus auparavant**.
- Compare avec le rapport du lancement précédent pour signaler les endpoints qui étaient présents avant et qui ont **disparu** cette fois.
- Produit un rapport HTML au thème sombre, dans le même style que Check-Security : cartes de résumé, barre de classification, évolution depuis le dernier lancement, graphique d'historique, recherche en direct, pastilles de filtre et colonnes triables.
- Purge automatiquement ses propres anciens rapports (`-PurgeDays`, 60 par défaut — la baseline n'est jamais purgée).
- Affiche une notification bureau avec un résumé en une ligne à la fin du lancement.
- Peut restreindre tout l'audit à un seul processus (`-ProcessName`).

## Ce qu'il ne fait *pas*

- Il ne décode **pas** le trafic QUIC/HTTP3 — les paquets UDP:443 sont comptés, pas inspectés (le chiffrement propre à QUIC rend cela nettement plus complexe que pour du TLS-over-TCP, et c'est hors du périmètre de cet outil).
- Il ne gère **pas** les en-têtes d'extension IPv6 dans le parseur de paquets.
- Il ne réassemble **pas** plus de deux segments TCP contigus, et ne peut pas récupérer d'une perte de paquet ou d'un réordonnancement — un ClientHello coupé en plusieurs segments désordonnés peut être manqué.
- Il ne remplace **pas** un vrai outil de capture réseau pour une investigation approfondie — si `Shadow-Traffic` signale quelque chose de suspect, une vraie capture de paquets (Wireshark) reste l'étape suivante appropriée pour une investigation complète.
- Il ne vérifie **pas** la santé de votre connexion, de votre configuration DNS, ou de vos adaptateurs — c'est le rôle de [Check-Network](https://github.com/NephVx2/Check-Network).
- Il ne bloque **rien** lui-même — il observe et rapporte, c'est tout. Le blocage, c'est le rôle de [Block-Telemetry](https://github.com/NephVx2/Block-Telemetry).

## Prérequis

- Windows 10 (1809+) ou Windows 11 — `pktmon` (utilisé pour `-CaptureSNI`) est natif à partir de ces versions.
- PowerShell 5.1 (intégré à Windows) ou PowerShell 7+.
- Les droits administrateur ne sont requis **que** pour `-CaptureSNI`. Le script demande l'élévation automatiquement (UAC) quand ce flag est utilisé ; l'audit TCP de base fonctionne sans droits admin.
- [Block-Telemetry](https://github.com/NephVx2/Block-Telemetry) est optionnel mais fortement recommandé — sans lui, tous les endpoints apparaîtront en « Unclassified » plutôt qu'en Known/ANOMALY, faute de liste de comparaison.

## Premier lancement (étape par étape)

Windows bloque par défaut les scripts téléchargés depuis internet (Mark of the Web). Si vous double-cliquez sur le fichier `.ps1` ou voyez un avertissement indiquant que le script est bloqué, c'est normal et attendu pour n'importe quel script PowerShell téléchargé — pas spécifique à celui-ci.

1. Clic droit sur `Shadow-Traffic.ps1` → **Propriétés** → cochez **Débloquer** (bas de l'onglet Général) → **OK**.
2. Ou, depuis une fenêtre PowerShell dans le dossier du script :
   ```powershell
   Unblock-File .\Shadow-Traffic.ps1
   ```
3. Si l'exécution de scripts est entièrement désactivée sur votre machine, autorisez l'exécution des scripts créés localement/débloqués :
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
4. Lancez-le (voir [Démarrage rapide](#demarrage-rapide) ci-dessous).

Pour un guide plus détaillé (avec l'explication de chaque avertissement), voir le guide [Script-blocked-Look-at-this](https://github.com/NephVx2/Script-blocked-Look-at-this).

## Démarrage rapide

Vérifier que le script fonctionne correctement sur votre machine (aucune capture, aucun droit admin requis — exécute 33 vérifications internes puis quitte) :
```powershell
.\Shadow-Traffic.ps1 -SelfTest
```
Voir [Self-test](#self-test) pour le détail de ce qui est couvert.

Audit TCP de base sur 2 minutes, sans droits admin :
```powershell
.\Shadow-Traffic.ps1
```

Audit complet avec capture SNI (droits admin requis — une invite UAC apparaîtra) :
```powershell
.\Shadow-Traffic.ps1 -CaptureSNI
```

Fenêtre plus longue, un seul processus ciblé :
```powershell
.\Shadow-Traffic.ps1 -CaptureSNI -DurationSeconds 300 -ProcessName nvcontainer
```

Lancement silencieux pour une tâche planifiée (les rapports sont quand même écrits, pas de sortie console, pas de notification) :
```powershell
.\Shadow-Traffic.ps1 -CaptureSNI -Silent -NoToast
```

## Raccourci bureau

1. Clic droit sur le Bureau → **Nouveau** → **Raccourci**.
2. Collez ceci comme emplacement (ajustez le chemin vers l'endroit où vous avez enregistré le script) :
   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Chemin\Vers\Shadow-Traffic.ps1" -CaptureSNI
   ```
3. Nommez-le, terminez, et c'est prêt — le script demande lui-même l'élévation quand `-CaptureSNI` est utilisé, il n'y a rien d'autre à configurer.

## Paramètres

| Paramètre | Défaut | Description |
|---|---|---|
| `-DurationSeconds <N>` | `120` | Durée de la fenêtre d'observation, en secondes. L'échantillonnage TCP et la capture SNI (si activée) tournent tous les deux pendant cette même durée. |
| `-BlockTelemetryPath <chemin>` | auto-détecté | Chemin vers `Block-Telemetry.ps1`. Si omis, le script le cherche dans son propre dossier. |
| `-IncludeLocal` | désactivé | Inclut les IP privées/loopback (192.168.x, 10.x, 127.0.0.1...) dans les résultats. Exclues par défaut car rarement intéressantes. |
| `-SkipSlowChecks` | désactivé | Désactive les résolutions DNS inverse (PTR) et ASN, pour un lancement plus rapide. Les endpoints sans SNI capturé n'apparaîtront alors que comme des IP brutes. |
| `-CaptureSNI` | désactivé | Active la capture de paquets via `pktmon` pour extraire les vrais noms d'hôte de la poignée de main TLS. **Nécessite les droits administrateur** (déclenche l'UAC). |
| `-ProcessName <nom>` | aucun | Restreint l'audit aux connexions appartenant aux processus correspondant à ce nom (correspondance partielle, insensible à la casse). |
| `-PurgeDays <N>` | `60` | Supprime les propres rapports du script (json/csv/html/log) plus vieux que N jours. `0` désactive la purge. Le fichier de baseline n'est jamais purgé. |
| `-NoToast` | désactivé | Désactive la notification bureau affichée à la fin du lancement. |
| `-DebugClientHello` | désactivé | Sauvegarde en hexadécimal tout ClientHello détecté par le parseur mais dont le SNI n'a pas pu être extrait (direct ou après réassemblage), dans un sous-dossier `Debug-ClientHello\` — utile pour signaler un bug du parseur. |
| `-SelfTest` | désactivé | Exécute la suite de tests intégrée (33 assertions) et quitte. Aucune capture réelle, aucun droit admin requis. |
| `-Silent` | désactivé | Réduit la sortie console au minimum. Les logs et rapports sont quand même écrits normalement. |

## Lire la sortie console

Un lancement typique affiche :

1. Une bannière d'en-tête encadrée avec le nom du script et sa version.
2. Une ligne **Reference** : Block-Telemetry a-t-il été trouvé (✓) ou non (!), et combien de domaines bloqués/en liste blanche ont été chargés.
   ```
   18:40:12  ✓  Reference           │ Block-Telemetry : 227 blocked domains  ·  71 whitelisted
   ```
3. Une barre de progression en direct pendant l'échantillonnage des connexions, mise à jour sur place. Elle devient une ligne ✓ une fois la fenêtre terminée :
   ```
   18:42:07  ·  Capture             │ ████████░░░░░░░░░░░░   45/120 s  ·  12 endpoints
   ```
4. Un bloc **SUMMARY** — une ligne par catégorie, avec une barre empilée montrant la répartition des endpoints entre anomalies (rouge), connus (vert) et non classés (jaune) :
   ```
   ·  Endpoints observed   18   ████████████████████
   ✗  Anomalies             1   blocked but reachable
   ✓  Known                 6   whitelist, normal
   !  Unclassified         11   to review
   +  New                   3   never seen before
   -  Vanished              2   present in the previous run, absent now
   ```
   Une icône devient un ✓ vert quand son compteur est à zéro (anomalies, non classés).
5. Si des anomalies ont été trouvées, un tableau **ANOMALIES** les listant une par une — c'est la section à regarder en premier.
6. Un tableau **UNCLASSIFIED**, trié par fréquence d'apparition, avec les colonnes `TARGET │ PROCESS │ COUNT │ SOURCE`. Les endpoints jamais vus auparavant reçoivent une icône `+` et un tag `NEW`. `SOURCE` indique d'où vient le nom : `SNI`, `PTR`, l'ASN (organisation et numéro d'AS, par ex. `Microsoft Corporation, US (AS8075)` — le rapport HTML garde le texte complet du registre), ou `no name` s'il s'agit d'une IP brute. Les noms de cibles de plus de 52 caractères sont raccourcis avec `...` dans la console uniquement — les rapports contiennent toujours le nom complet.
7. Le cas échéant, un tableau **VANISHED SINCE LAST RUN** (endpoints présents dans le rapport précédent mais pas cette fois — pas forcément un problème, une connexion peut être ponctuelle).
8. Si la capture SNI est activée et qu'un SNI n'a pas pu être rattaché à une connexion TCP (connexion trop courte pour être échantillonnée), un tableau **SNI CAPTURED WITH NO MATCHING TCP CONNECTION**.
9. Une bannière finale **✓ AUDIT COMPLETE** listant tous les fichiers générés (rapport HTML, export JSON, export CSV, log), puis la question proposant d'ouvrir le rapport HTML et le cadre « Press ENTER to close this window ».

## Comment fonctionne la classification

Chaque endpoint reçoit l'une de ces catégories, en fonction de son nom résolu (SNI en priorité, puis PTR, puis ASN, puis l'IP brute) comparé aux listes de Block-Telemetry :

- **ANOMALY — Blocked domain but reachable (possible bypass)** : le nom correspond à un domaine bloqué par Block-Telemetry, mais la connexion est quand même passée. C'est la catégorie à investiguer en priorité : une application utilise peut-être une IP codée en dur, du DNS-over-HTTPS, ou un autre chemin qui contourne complètement votre fichier hosts.
- **Known (whitelist, normal)** : le nom correspond à quelque chose explicitement mis en liste blanche dans Block-Telemetry — normal, rien à faire.
- **Unclassified** : le nom (ou l'IP) ne correspond à aucune des deux listes. C'est là que passera l'essentiel de votre temps de revue — la plupart de ces cas sont parfaitement normaux (CDN, backends d'application, services pas encore catégorisés), mais c'est aussi là qu'un véritable nouveau traqueur apparaîtrait en premier.

En plus de la catégorie, chaque endpoint peut aussi être marqué :
- **`NEW`** (une icône `+` dans la console) : jamais apparu dans la baseline d'un lancement précédent.
- Listé sous **Vanished** : présent au lancement précédent, absent cette fois.

## Le rapport HTML

Le rapport reprend le style visuel de Check-Security (en-tête avec logo et une barre d'infos indiquant la machine, la date, l'OS et les réglages de capture). De haut en bas :

- Une **bannière** : rouge, avec des liens vers chaque anomalie, si des domaines bloqués étaient encore joignables ; un avertissement si la référence Block-Telemetry est introuvable ; une boîte verte « no anomaly » sinon.
- Une **barre de classification** qui répartit les endpoints entre anomalies, connus et non classés.
- Un bloc **Evolution since the last run** listant les endpoints nouveaux et disparus, et un petit **graphique d'historique** du nombre de non classés sur les derniers lancements (avec min/max).
- Des **cartes de résumé** : Total / Anomalies / Known / Unclassified / New / Vanished.
- Le **tableau détaillé**, avec une recherche en direct, des pastilles de filtre (All / Anomalies / Unclassified / Known / New) et des colonnes triables. Chaque ligne affiche la cible, sa catégorie, le processus propriétaire (avec son PID), le port, le nombre de fois où elle a été vue, et la source du nom.
- Le cas échéant, un tableau **Vanished since the last run** et un tableau **SNI captured with no matching TCP connection** — les mêmes listes que dans la console.

Les noms issus du réseau (SNI, PTR, ASN, noms de processus) sont échappés en HTML, et les noms SNI/PTR contenant autre chose que des lettres, chiffres ou `_ . : -` sont écartés dès la capture.

## Rapports et fichiers

Tous les fichiers sont écrits dans `Desktop\Maintenance_Reports\Shadow-Traffic\` :

| File | Contenu |
|---|---|
| `Shadow-Traffic_<horodatage>.html` | Le rapport interactif décrit ci-dessus. |
| `Shadow-Traffic_<horodatage>.json` | Instantané complet et exploitable par machine du lancement (tous les endpoints, comptages, catégories). |
| `Shadow-Traffic_Unclassified_<horodatage>.csv` | Uniquement les endpoints Unclassified et ANOMALY, pour une revue rapide dans Excel. |
| `Shadow-Traffic_<horodatage>.log` | Journal de lancement en texte brut (horodatages, avertissements, erreurs, une ligne de synthèse du run et la mise à jour de la baseline). |
| `Baseline_Shadow-Traffic.json` | Historique persistant utilisé pour détecter les endpoints « jamais vus auparavant ». Jamais purgé par `-PurgeDays`. |

## Intégration avec Block-Telemetry

`Shadow-Traffic` lit les listes de domaines de [Block-Telemetry](https://github.com/NephVx2/Block-Telemetry) (bloqués + liste blanche) pour classer ce qu'il observe — il ne modifie en aucune façon Block-Telemetry ou votre fichier hosts, il se contente de lire la liste à des fins de comparaison. Si Block-Telemetry n'est pas trouvé (mauvais chemin, non installé, ou renommé), l'audit tourne quand même, mais tous les endpoints apparaîtront en « Unclassified » faute de liste de comparaison. Utilisez `-BlockTelemetryPath` pour pointer vers le fichier exact si la détection automatique ne le trouve pas.

## Confidentialité

Le chemin de capture SNI (`-CaptureSNI`) voit nécessairement à quels noms d'hôte votre machine se connecte — c'est tout son intérêt. La capture de paquets brute (fichiers `.etl`/`.pcapng`) est supprimée immédiatement après extraction du SNI ; rien n'est conservé au-delà du nom d'hôte parsé dans les rapports décrits ci-dessus. Tout se passe localement : aucune donnée n'est envoyée où que ce soit, à l'exception des requêtes DNS (optionnelles, désactivables via `-SkipSlowChecks`) vers Team Cymru pour la résolution ASN.

## Self-test

```powershell
.\Shadow-Traffic.ps1 -SelfTest
```
Exécute 33 assertions internes couvrant la classification des IP, la classification des domaines, le parseur de paquets (construit à partir de fixtures TLS créées à la main, dont un vrai ClientHello Windows/Edge tronqué qui avait autrefois cassé l'extraction du SNI), le réassemblage TCP, la détection UDP/QUIC, la construction des requêtes ASN, le cycle complet de la baseline, et la sûreté des sorties (échappement HTML, validation des noms d'hôte, protection CSV contre les formules, et un export HTML complet de bout en bout). Aucune capture réelle, aucun droit admin requis.

## Dépannage

**`-CaptureSNI` échoue / le SNI n'apparaît jamais dans les résultats.**
Assurez-vous d'exécuter en tant qu'administrateur — le script devrait demander l'élévation automatiquement, mais si ce n'est pas le cas (par exemple lancé depuis un shell déjà élevé mais restreint), relancez-le manuellement en admin. Vérifiez aussi que `pktmon` est disponible (`Get-Command pktmon`) — il est natif à partir de Windows 10 1809+ et Windows 11.

**Tout apparaît en « Unclassified ».**
Block-Telemetry n'a pas été trouvé. Passez `-BlockTelemetryPath` en pointant vers votre `Block-Telemetry.ps1` réel, ou placez les deux scripts dans le même dossier.

**Un ClientHello a été détecté mais aucun SNI n'a été extrait.**
Relancez avec `-DebugClientHello` — cela sauvegarde les octets bruts dans `Debug-ClientHello\` pour permettre d'inspecter le cas (et de le signaler, s'il s'avère qu'il s'agit d'un bug du parseur).

**Le lancement semble lent.**
`-SkipSlowChecks` désactive les résolutions DNS inverse et ASN, qui sont la principale source de latence quand de nombreuses IP non classées doivent être nommées.
