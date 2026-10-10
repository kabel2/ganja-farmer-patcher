# Ganja Farmer Patcher

**https://kabel2.github.io/ganja-farmer-patcher/**

The original Ganja Farmer server has been shut down, and the game no longer
starts without it. This patcher points the original APK (version 147) to a
community server. Everything happens in your browser: the APK is never uploaded,
and no APK is distributed here.

## Usage

1. Open the page and choose the original `.apk` (v147, not an XAPK).
2. Download the patched APK and install it (Android 7 or newer).
   Uninstall an existing original installation first.
3. On devices with 16 KB memory pages a compatibility notice appears at
   startup. Just tap *OK*.

Command line (Node ≥ 21): `node cli.mjs original.apk patched.apk [server-url]`

## How it works

| File | Contents |
|---|---|
| `index.html` | User interface |
| `apkpatch.js` | The patcher, no dependencies, runs in the browser and in Node |
| `key.js`, `keys/` | Signing key (public on purpose, see below) |
| `cli.mjs` | Command line version |

1. In `assets/bin/Data/Managed/Metadata/global-metadata.dat` (IL2CPP metadata)
   the string literal holding the old server URL is located via the metadata
   header, replaced with the new URL, and its length field is updated.
2. The APK is rebuilt: all other entries are copied unchanged, old signature
   files are removed, and uncompressed entries are aligned like `zipalign -p`.
3. It is signed with APK Signature Scheme v2 using the same layout as
   `apksigner` (signing block and central directory on 4096-byte boundaries,
   stale `stamp-cert-sha256` dropped). With the first, different layout the
   compatibility mode did not kick in on a 16 KB device and the game aborted
   with “Not enough storage space”.

The browser and Node produce byte-identical results.

## The key

`CN=Ganja Farmer Patcher`, RSA 2048, SHA-256 fingerprint
`35:AD:36:5D:4B:59:D7:1B:88:F2:37:B1:20:61:80:B8:DA:6D:D8:5B:78:AA:B4:27:40:64:E8:A0:75:15:A9:21`.

It is public on purpose. Its only job is to give every patched APK the same
signature, so later versions install over earlier ones without uninstalling
(and thus without losing your progress). It does not establish any trust.
Switching to a new key would break exactly these updates.

## Legal

Unofficial fan project, not affiliated with the developers of Ganja Farmer.
No game code or content is distributed; the patcher only modifies the APK you
bring yourself.
