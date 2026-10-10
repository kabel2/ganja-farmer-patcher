// Ganja Farmer APK patcher: runs unchanged in the browser and in Node (>= 21).
//
// 1. finds the dead server URL in global-metadata.dat (IL2CPP string literal)
//    and replaces it with our server, fixing the literal's length field
// 2. rebuilds the APK: all other entries are copied raw (no recompression),
//    old v1 signature files are dropped, stored entries are aligned (zipalign)
// 3. signs it with APK Signature Scheme v2 (Android 7+) using the patcher key
//
// No dependencies: ZIP handling, CRC32 and the v2 signing block are done here,
// (de)compression and crypto come from CompressionStream / WebCrypto.

import { KEY_PKCS8_B64, CERT_B64, SPKI_B64 } from './key.js';

export const OLD_URL = 'https://server.ganja-farmer.net/api/';
export const DEFAULT_URL = 'https://leguan3.ipv64.net/api/';
const METADATA = 'assets/bin/Data/Managed/Metadata/global-metadata.dat';
const METADATA_MAGIC = 0xfab11baf;

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const V2_BLOCK_ID = 0x7109871a;
const PADDING_BLOCK_ID = 0x42726577;
const RSA_PKCS1_SHA256 = 0x0103;
const CHUNK = 1 << 20;
// Layout copied from apksigner: signing block and central directory start on a
// page, and the stale stamp-cert-sha256 marker is dropped. Without both, the
// 16 KB page-size compat mode was not applied on a 16 KB API 37 emulator and
// Unity 2018 failed with "Not enough storage space" (not bisected further).
const PAGE = 4096;

export class PatchError extends Error {}

const enc = new TextEncoder();

// ---------------------------------------------------------------- helpers

function view(b) {
  return new DataView(b.buffer, b.byteOffset, b.byteLength);
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function u32(v) {
  const b = new Uint8Array(4);
  view(b).setUint32(0, v, true);
  return b;
}

function u64(v) {
  const b = new Uint8Array(8);
  view(b).setBigUint64(0, BigInt(v), true);
  return b;
}

// length-prefixed (uint32 LE), the basic building block of the v2 format
function lp(...parts) {
  const body = concat(...parts);
  return concat(u32(body.length), body);
}

function b64(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(b) {
  let c = 0xffffffff;
  for (let i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

async function transform(data, stream) {
  const out = await new Response(new Blob([data]).stream().pipeThrough(stream)).arrayBuffer();
  return new Uint8Array(out);
}

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

// ---------------------------------------------------------------- ZIP read

function readZip(buf) {
  const dv = view(buf);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (dv.getUint32(i, true) === SIG_EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new PatchError('This is not a valid APK file (not a ZIP archive).');
  const count = dv.getUint16(eocd + 10, true);
  const cdOff = dv.getUint32(eocd + 16, true);
  if (count === 0xffff || cdOff === 0xffffffff) throw new PatchError('ZIP64 archives are not supported.');

  const dec = new TextDecoder();
  const entries = [];
  let p = cdOff;
  for (let i = 0; i < count; i++) {
    if (dv.getUint32(p, true) !== SIG_CENTRAL) throw new PatchError('Corrupt ZIP central directory.');
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const e = {
      versionMade: dv.getUint16(p + 4, true),
      versionNeeded: dv.getUint16(p + 6, true),
      flags: dv.getUint16(p + 8, true) & ~0x0008, // we write sizes up front, no data descriptor
      method: dv.getUint16(p + 10, true),
      time: dv.getUint16(p + 12, true),
      date: dv.getUint16(p + 14, true),
      crc: dv.getUint32(p + 16, true),
      csize: dv.getUint32(p + 20, true),
      usize: dv.getUint32(p + 24, true),
      intAttr: dv.getUint16(p + 36, true),
      extAttr: dv.getUint32(p + 38, true),
      localOff: dv.getUint32(p + 42, true),
      nameBytes: buf.subarray(p + 46, p + 46 + nameLen),
    };
    e.name = dec.decode(e.nameBytes);
    const lo = e.localOff;
    if (dv.getUint32(lo, true) !== SIG_LOCAL) throw new PatchError(`Corrupt ZIP entry: ${e.name}`);
    const dataOff = lo + 30 + dv.getUint16(lo + 26, true) + dv.getUint16(lo + 28, true);
    e.data = buf.subarray(dataOff, dataOff + e.csize);
    entries.push(e);
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries.sort((a, b) => a.localOff - b.localOff);
}

// ---------------------------------------------------------------- ZIP write

// zipalign -p semantics: stored entries 4-byte aligned, stored .so page aligned
// (16 KB, which also satisfies 4 KB devices). Compressed entries need nothing.
function alignmentOf(e) {
  if (e.method !== 0) return 0;
  return e.name.endsWith('.so') ? 16384 : 4;
}

function writeZip(entries) {
  // layout pass: offsets and alignment padding
  let off = 0;
  for (const e of entries) {
    const base = off + 30 + e.nameBytes.length;
    const a = alignmentOf(e);
    // padding lives in an extra field 0xd935 {uint16 alignment, zeros} like apksigner does
    e.extraLen = a ? 6 + ((a - ((base + 6) % a)) % a) : 0;
    e.newOff = off;
    off = base + e.extraLen + e.data.length;
  }

  // zero padding after the last entry, so the signing block starts on a page
  const body = new Uint8Array(off + ((PAGE - (off % PAGE)) % PAGE));
  const bv = view(body);
  for (const e of entries) {
    let p = e.newOff;
    bv.setUint32(p, SIG_LOCAL, true);
    bv.setUint16(p + 4, e.versionNeeded, true);
    bv.setUint16(p + 6, e.flags, true);
    bv.setUint16(p + 8, e.method, true);
    bv.setUint16(p + 10, e.time, true);
    bv.setUint16(p + 12, e.date, true);
    bv.setUint32(p + 14, e.crc, true);
    bv.setUint32(p + 18, e.data.length, true);
    bv.setUint32(p + 22, e.usize, true);
    bv.setUint16(p + 26, e.nameBytes.length, true);
    bv.setUint16(p + 28, e.extraLen, true);
    body.set(e.nameBytes, p + 30);
    p += 30 + e.nameBytes.length;
    if (e.extraLen) {
      bv.setUint16(p, 0xd935, true);
      bv.setUint16(p + 2, e.extraLen - 4, true);
      bv.setUint16(p + 4, alignmentOf(e), true);
      p += e.extraLen; // rest is already zero
    }
    body.set(e.data, p);
  }

  const cd = new Uint8Array(entries.reduce((n, e) => n + 46 + e.nameBytes.length, 0));
  const cv = view(cd);
  let p = 0;
  for (const e of entries) {
    cv.setUint32(p, SIG_CENTRAL, true);
    cv.setUint16(p + 4, e.versionMade, true);
    cv.setUint16(p + 6, e.versionNeeded, true);
    cv.setUint16(p + 8, e.flags, true);
    cv.setUint16(p + 10, e.method, true);
    cv.setUint16(p + 12, e.time, true);
    cv.setUint16(p + 14, e.date, true);
    cv.setUint32(p + 16, e.crc, true);
    cv.setUint32(p + 20, e.data.length, true);
    cv.setUint32(p + 24, e.usize, true);
    cv.setUint16(p + 28, e.nameBytes.length, true);
    // extra, comment, disk number: 0
    cv.setUint16(p + 36, e.intAttr, true);
    cv.setUint32(p + 38, e.extAttr, true);
    cv.setUint32(p + 42, e.newOff, true);
    cd.set(e.nameBytes, p + 46);
    p += 46 + e.nameBytes.length;
  }

  const eocd = new Uint8Array(22);
  const ev = view(eocd);
  ev.setUint32(0, SIG_EOCD, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cd.length, true);
  ev.setUint32(16, body.length, true);
  return { body, cd, eocd };
}

// ---------------------------------------------------------------- metadata

function patchMetadata(m, newUrl) {
  const dv = view(m);
  if (m.length < 24 || dv.getUint32(0, true) !== METADATA_MAGIC) {
    throw new PatchError('global-metadata.dat has an unknown format.');
  }
  // header: stringLiteralOffset/Size (entries {uint32 length, int32 dataIndex}),
  //         stringLiteralDataOffset (UTF-8 blob)
  const litOff = dv.getUint32(8, true);
  const litSize = dv.getUint32(12, true);
  const dataOff = dv.getUint32(16, true);
  const old = enc.encode(OLD_URL);
  const neu = enc.encode(newUrl);
  if (neu.length > old.length) throw new PatchError(`The new URL is too long (max. ${old.length} characters).`);

  let hit = -1;
  for (let e = litOff; e + 8 <= litOff + litSize; e += 8) {
    if (dv.getUint32(e, true) !== old.length) continue;
    const at = dataOff + dv.getInt32(e + 4, true);
    if (m.subarray(at, at + old.length).every((c, i) => c === old[i])) {
      if (hit >= 0) throw new PatchError('The server URL occurs more than once, unexpected APK version.');
      hit = e;
    }
  }
  if (hit < 0) {
    throw new PatchError('Server URL not found. Is this the original, unpatched Ganja Farmer APK (v147)?');
  }
  // the blob is packed: write the shorter URL into the old footprint, zero the
  // rest and shorten the length field, so the following literal stays untouched
  const at = dataOff + dv.getInt32(hit + 4, true);
  m.fill(0, at, at + old.length);
  m.set(neu, at);
  dv.setUint32(hit, neu.length, true);
}

// ---------------------------------------------------------------- v2 signing

async function chunkedDigest(sections, onChunk) {
  const digests = [];
  const total = sections.reduce((n, s) => n + Math.ceil(s.length / CHUNK), 0);
  for (const s of sections) {
    for (let i = 0; i < s.length; i += CHUNK) {
      const c = s.subarray(i, Math.min(s.length, i + CHUNK));
      digests.push(await sha256(concat(Uint8Array.of(0xa5), u32(c.length), c)));
      onChunk?.(digests.length / total);
    }
  }
  return sha256(concat(Uint8Array.of(0x5a), u32(digests.length), ...digests));
}

async function signingBlock(body, cd, eocd, onChunk) {
  // EOCD's CD offset already points to where the block will be inserted,
  // which is exactly what the v2 digest expects
  const digest = await chunkedDigest([body, cd, eocd], onChunk);
  const cert = b64(CERT_B64);
  const signedData = concat(
    lp(lp(u32(RSA_PKCS1_SHA256), lp(digest))), // digests
    lp(lp(cert)), // certificates
    lp(), // additional attributes
  );
  const key = await crypto.subtle.importKey(
    'pkcs8', b64(KEY_PKCS8_B64), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'],
  );
  const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, signedData));
  const signer = concat(
    lp(signedData),
    lp(lp(u32(RSA_PKCS1_SHA256), lp(signature))),
    lp(b64(SPKI_B64)),
  );
  const value = lp(lp(signer));
  const pair = concat(u64(4 + value.length), u32(V2_BLOCK_ID), value);
  // pad the whole block (incl. its leading size field) to a page multiple
  const unpadded = 8 + pair.length + 8 + 16;
  let padLen = (PAGE - (unpadded % PAGE)) % PAGE;
  if (padLen && padLen < 12) padLen += PAGE; // a pair needs 12 bytes of header
  const padding = padLen
    ? concat(u64(padLen - 8), u32(PADDING_BLOCK_ID), new Uint8Array(padLen - 12))
    : new Uint8Array(0);
  const size = pair.length + padding.length + 8 + 16;
  return concat(u64(size), pair, padding, u64(size), enc.encode('APK Sig Block 42'));
}

// ---------------------------------------------------------------- main

/**
 * @param {ArrayBuffer|Uint8Array} apk  original Ganja Farmer APK
 * @param {object} [opts]
 * @param {string} [opts.url]  new server base URL (max. 36 chars)
 * @param {(stage: string, fraction?: number) => void} [opts.onProgress]
 * @returns {Promise<Blob>} the patched, signed APK
 */
export async function patchApk(apk, { url = DEFAULT_URL, onProgress } = {}) {
  const buf = apk instanceof Uint8Array ? apk : new Uint8Array(apk);
  onProgress?.('Reading APK');
  const entries = readZip(buf);

  if (!entries.some((e) => e.name === 'AndroidManifest.xml')) {
    if (entries.some((e) => e.name.endsWith('.apk'))) {
      throw new PatchError('This is an XAPK/APKS bundle. Please use the single APK file (v147).');
    }
    throw new PatchError('This is not an Android app (AndroidManifest.xml is missing).');
  }
  const meta = entries.find((e) => e.name === METADATA);
  if (!meta) throw new PatchError('Not a Unity IL2CPP app (global-metadata.dat is missing). Is this Ganja Farmer?');

  onProgress?.('Replacing server URL');
  let m;
  if (meta.method === 8) m = await transform(meta.data, new DecompressionStream('deflate-raw'));
  else if (meta.method === 0) m = meta.data.slice();
  else throw new PatchError(`Unknown compression (${meta.method}) for global-metadata.dat.`);
  patchMetadata(m, url);
  meta.data = await transform(m, new CompressionStream('deflate-raw'));
  meta.method = 8;
  meta.crc = crc32(m);
  meta.usize = m.length;

  // drop the original v1 (JAR) signature and the Play source stamp marker;
  // the v2/v3/stamp blocks vanish with the rebuild anyway
  const isOldSig = (n) => n === 'META-INF/MANIFEST.MF' || n === 'stamp-cert-sha256'
    || /^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(n);
  onProgress?.('Repacking APK');
  const { body, cd, eocd } = writeZip(entries.filter((e) => !isOldSig(e.name)));

  onProgress?.('Signing', 0);
  const block = await signingBlock(body, cd, eocd, (f) => onProgress?.('Signing', f));
  view(eocd).setUint32(16, body.length + block.length, true);

  onProgress?.('Done', 1);
  return new Blob([body, block, cd, eocd], { type: 'application/vnd.android.package-archive' });
}
