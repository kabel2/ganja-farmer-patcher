# Ganja Farmer Patcher

**https://kabel2.github.io/ganja-farmer-patcher/**

Der Originalserver von Ganja Farmer ist abgeschaltet, seitdem startet das Spiel
nicht mehr. Dieser Patcher stellt die originale APK (Version 147) auf einen
Community-Server um. Alles passiert im Browser: Die APK wird nicht hochgeladen,
und hier wird keine APK bereitgestellt.

## Benutzung

1. Seite öffnen, die originale `.apk` (v147, keine XAPK) auswählen.
2. Gepatchte APK herunterladen und installieren (ab Android 7).
   Eine vorhandene Original-Installation vorher deinstallieren.
3. Auf Geräten mit 16-KB-Speicherseiten erscheint beim Start ein
   Kompatibilitätshinweis, einfach mit *OK* bestätigen.

Kommandozeile (Node ≥ 21): `node cli.mjs original.apk gepatcht.apk [server-url]`

## Wie es funktioniert

| Datei | Inhalt |
|---|---|
| `index.html` | Oberfläche |
| `apkpatch.js` | Patcher, ohne Abhängigkeiten, läuft in Browser und Node |
| `key.js`, `keys/` | Signierschlüssel (absichtlich öffentlich, s. u.) |
| `cli.mjs` | Kommandozeilen-Variante |

1. In `assets/bin/Data/Managed/Metadata/global-metadata.dat` (IL2CPP-Metadaten)
   wird der String-Literal-Eintrag mit der alten Server-URL über den
   Metadata-Header gesucht, durch die neue URL ersetzt und das Längenfeld angepasst.
2. Die APK wird neu aufgebaut: Alle anderen Einträge werden unverändert kopiert,
   alte Signaturdateien entfernt, unkomprimierte Einträge wie bei `zipalign -p`
   ausgerichtet.
3. Signiert wird mit APK Signature Scheme v2, im selben Layout wie `apksigner`
   (Signaturblock und Central Directory auf 4096-Byte-Grenzen, ohne die alte
   `stamp-cert-sha256`). Mit dem ersten, abweichenden Layout griff auf einem
   16-KB-Gerät der Kompatibilitätsmodus nicht und das Spiel brach mit
   „Not enough storage space“ ab.

Browser und Node erzeugen bytegleiche Ergebnisse.

## Der Schlüssel

`CN=Ganja Farmer Patcher`, RSA 2048, SHA-256-Fingerprint
`35:AD:36:5D:4B:59:D7:1B:88:F2:37:B1:20:61:80:B8:DA:6D:D8:5B:78:AA:B4:27:40:64:E8:A0:75:15:A9:21`.

Er ist bewusst öffentlich. Er sorgt nur dafür, dass alle gepatchten APKs dieselbe
Signatur tragen, damit sich spätere Versionen ohne Deinstallation (und damit ohne
Verlust des Spielstands) installieren lassen. Vertrauen stiftet er keines.
Ein neuer Schlüssel würde genau diese Updates brechen.

## Rechtliches

Inoffizielles Fanprojekt, nicht mit den Entwicklern von Ganja Farmer verbunden.
Es wird kein Code oder Inhalt des Spiels verbreitet, der Patcher verändert nur
die APK, die du selbst mitbringst.
