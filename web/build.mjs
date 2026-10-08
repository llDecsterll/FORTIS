import { build } from "vite";
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

// Production JSX is handled by esbuild. Avoid bundling the dev-only TS config.
await build({ configFile: false, base:'./', esbuild: { jsx: "automatic" }, build: { outDir: "dist", sourcemap: false } });
const hash=createHash('sha256');
async function hashTree(dir) {
  for(const item of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))) {
    const path=`${dir}/${item.name}`;
    if(item.isDirectory()) await hashTree(path);
    else { hash.update(path); hash.update(await readFile(path)); }
  }
}
await hashTree('dist');
const version=hash.digest('hex').slice(0,20);
const html=await readFile('dist/index.html','utf8');
const versionedHtml=html.replace(/src="(\/(?!assets\/)[^"?]+\.js)(?:\?[^\"]*)?"/g,`src="$1?v=${version}"`);
await writeFile('dist/index.html',versionedHtml.replace('</head>',`<meta name="app-version" content="${version}" /></head>`));
await writeFile('dist/version.json',JSON.stringify({version}));
