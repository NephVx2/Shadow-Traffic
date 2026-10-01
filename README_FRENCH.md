<a id="english"></a>
## English

*[Jump straight to French ↓](#french)*

# Shadow-Traffic v2.2.4 — Release Notes

Changes since [v2.2.2](RELEASE_NOTES_v2_2_2.md): v2.2.3 was never published separately, so its changes are folded in here alongside v2.2.4's — two real-world bug fixes and a documentation addition.

### Fixed

- **`-BlockTelemetryPath` auto-detection was silently failing even with both scripts in the same folder.** The default lookup path still pointed at `Block-Telemetry_v5_2.ps1` — Block-Telemetry's filename *before* its own v5.3 translation renamed it to `Block-Telemetry.ps1`. Shadow-Traffic's default was never updated to match, so every run without an explicit `-BlockTelemetryPath` printed a `[WARN] Block-Telemetry not found` and classified every endpoint as `Unclassified`, even when Block-Telemetry was sitting right next to it. Passing `-BlockTelemetryPath` explicitly always worked — only the automatic default was stale. Fixed; reproduced the exact side-by-side-folder scenario before shipping to confirm auto-detection now resolves correctly.

- **A run could print a raw, untranslated, OS-language pktmon error straight to the console** — e.g. a French `Erreur : impossible d'ouvrir le fichier '...etl': Le fichier spécifié est introuvable.` — instead of one of this script's own `[WARN]` lines, with nothing written to the log about it either. Two causes stacked:
  1. `pktmon.exe` is a native tool: a failure writes straight to its own stderr instead of throwing a catchable PowerShell exception, so a `try`/`catch` around it never saw it.
  2. The underlying trigger was a real race condition: `pktmon stop` can return before the ETW capture session has actually finished flushing and closing its `.etl` file on disk, so converting it immediately afterward could hit that file before it was ready — silently producing zero captured packets for the run.

  Fixed by checking `$LASTEXITCODE` after every `pktmon` call instead of relying on exceptions (so a real failure is always caught and logged through this script's own `Write-Log`, in English, regardless of the system's display language), and by adding a short pause between `pktmon stop` and the pcapng conversion so the file has time to be ready. Reproduced the exact failure with a stand-in `pktmon` before shipping, to confirm the raw error no longer leaks and the warning is logged cleanly instead.

### Documentation

- Added a **Screenshots** section to `README.md` / `README_FRENCH.md` (console banner + HTML report preview), positioned right below the table of contents, matching the layout used by [Check-Network](../Check-Network)'s README.

### Upgrading

- No breaking changes. If you were passing `-BlockTelemetryPath` explicitly as a workaround for the auto-detection bug, it's safe to drop it now, as long as `Block-Telemetry.ps1` sits in the same folder as `Shadow-Traffic.ps1`.

---

<a id="french"></a>
## Français

*[Remonter à la version anglaise ↑](#english)*

# Shadow-Traffic v2.2.4 — Notes de version

Changements depuis la [v2.2.2](RELEASE_NOTES_v2_2_2.md) : la v2.2.3 n'a jamais été publiée séparément, ses changements sont donc regroupés ici avec ceux de la v2.2.4 — deux correctifs de bugs réels et un ajout de documentation.

### Corrigé

- **L'auto-détection de `-BlockTelemetryPath` échouait silencieusement même avec les deux scripts dans le même dossier.** Le chemin par défaut pointait encore vers `Block-Telemetry_v5_2.ps1` — le nom de fichier de Block-Telemetry *avant* que sa propre traduction v5.3 le renomme en `Block-Telemetry.ps1`. Le défaut de Shadow-Traffic n'avait jamais été mis à jour en conséquence, donc tout lancement sans `-BlockTelemetryPath` explicite affichait un `[WARN] Block-Telemetry not found` et classait chaque endpoint en `Unclassified`, même quand Block-Telemetry se trouvait juste à côté. Passer `-BlockTelemetryPath` explicitement fonctionnait toujours — seul le défaut automatique était périmé. Corrigé ; le scénario exact (dossier avec les deux scripts côte à côte) a été reproduit avant livraison pour confirmer que l'auto-détection fonctionne désormais correctement.

- **Un lancement pouvait afficher une erreur `pktmon` brute, non traduite, dans la langue du système, directement dans la console** — par exemple un `Erreur : impossible d'ouvrir le fichier '...etl': Le fichier spécifié est introuvable.` en français — au lieu d'une des lignes `[WARN]` propres au script, sans rien d'écrit dans le log à ce sujet non plus. Deux causes empilées :
  1. `pktmon.exe` est un outil natif : un échec écrit directement sur sa propre sortie d'erreur au lieu de lever une exception PowerShell interceptable, donc un `try`/`catch` autour de l'appel ne la voyait jamais.
  2. Le déclencheur réel était une véritable condition de course : `pktmon stop` peut rendre la main avant que la session de capture ETW ait réellement fini de vider et de fermer son fichier `.etl` sur le disque, donc le convertir immédiatement après pouvait tomber sur ce fichier avant qu'il soit prêt — produisant silencieusement zéro paquet capturé pour ce run.

  Corrigé en vérifiant `$LASTEXITCODE` après chaque appel à `pktmon` au lieu de compter sur une exception (donc un vrai échec est désormais toujours intercepté et loggé via le `Write-Log` propre au script, en anglais, quelle que soit la langue d'affichage du système), et en ajoutant une courte pause entre `pktmon stop` et la conversion pcapng pour laisser le temps au fichier d'être prêt. L'échec exact a été reproduit avec un `pktmon` de substitution avant livraison, pour confirmer que l'erreur brute ne fuite plus et que l'avertissement est désormais loggé proprement.

### Documentation

- Ajout d'une section **Screenshots** à `README.md` / `README_FRENCH.md` (bannière console + aperçu du rapport HTML), positionnée juste sous le sommaire, sur le même modèle de mise en page que le README de [Check-Network](../Check-Network).

### Mise à jour

- Aucun changement cassant. Si vous passiez `-BlockTelemetryPath` explicitement pour contourner le bug d'auto-détection, vous pouvez désormais l'omettre sans risque, tant que `Block-Telemetry.ps1` se trouve dans le même dossier que `Shadow-Traffic.ps1`.
