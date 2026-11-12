import { build } from "esbuild";
import { mkdir, copyFile } from "node:fs/promises";
import { resolve } from "node:path";
await mkdir("public", { recursive: true });
await build({
  entryPoints: ["../control-panel/src/app.js"],
  bundle: true,
  minify: true,
  format: "esm",
  target: ["chrome120", "edge120"],
  outfile: "public/app.js",
  nodePaths: [resolve("node_modules")],
});
for (const file of [
  "index.html",
  "styles.css",
  "logo.png",
  "rajdhani.ttf",
  "FONT-LICENSE.txt",
])
  await copyFile("../control-panel/" + file, "public/" + file);
