import { copyFileSync, cpSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(fileURLToPath(new URL('..', import.meta.url)));
const source = resolve(repo, 'blog');
const output = resolve(repo, 'target', 'blog-pages');
const pages = [];

function walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walk(path);
    else if (entry.isFile() && extname(path) === '.html') pages.push(path);
  }
}

rmSync(output, { recursive: true, force: true });
mkdirSync(dirname(output), { recursive: true });
cpSync(source, output, { recursive: true });
walk(source);

let cleanRoutes = 0;
for (const page of pages) {
  const sourcePath = relative(source, page);
  if (sourcePath === 'index.html') continue;

  const route = sourcePath.slice(0, -'.html'.length);
  const destination = join(output, route, 'index.html');
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(page, destination);
  cleanRoutes += 1;
}

console.log(`Packaged ${pages.length} HTML pages with ${cleanRoutes} clean routes in target/blog-pages.`);
