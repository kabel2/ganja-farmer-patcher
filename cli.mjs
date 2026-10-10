#!/usr/bin/env node
// Same patcher as the website, from the command line:
//   node cli.mjs <original.apk> <out.apk> [server-url]
import { readFile, writeFile } from 'node:fs/promises';
import { patchApk, DEFAULT_URL } from './apkpatch.js';

const [input, output, url = DEFAULT_URL] = process.argv.slice(2);
if (!input || !output) {
  console.error('usage: node cli.mjs <original.apk> <out.apk> [server-url]');
  process.exit(2);
}

const t0 = Date.now();
let last = '';
const blob = await patchApk(await readFile(input), {
  url,
  onProgress: (stage) => { if (stage !== last) console.log(`  ${(last = stage)}`); },
});
await writeFile(output, new Uint8Array(await blob.arrayBuffer()));
console.log(`${output}: ${blob.size} bytes, ${url}, ${((Date.now() - t0) / 1000).toFixed(1)} s`);
