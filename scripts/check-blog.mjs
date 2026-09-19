import { readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(fileURLToPath(new URL('..', import.meta.url)));
const site = resolve(repo, 'blog');
const origin = 'https://hydir.wiki';
const errors = [];
const pages = [];
const idsByPage = new Map();
const refs = [];

function walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walk(path);
    else if (entry.isFile() && extname(path) === '.html') pages.push(path);
  }
}

function attrs(tag) {
  return Object.fromEntries([...tag.matchAll(/([\w-]+)="([^"]*)"/g)].map((match) => [match[1], match[2]]));
}

walk(site);
if (!pages.includes(resolve(site, 'index.html'))) errors.push('blog/index.html is missing');

for (const page of pages) {
  const html = readFileSync(page, 'utf8');
  const ids = new Set();
  idsByPage.set(page, ids);
  for (const tag of html.match(/<[^>]+>/g) ?? []) {
    const attributes = attrs(tag);
    if (attributes.id) {
      if (ids.has(attributes.id)) errors.push(`${relative(repo, page)}: duplicate id ${attributes.id}`);
      ids.add(attributes.id);
    }
    const name = /^<([\w-]+)/.exec(tag)?.[1]?.toLowerCase();
    if (!['a', 'img', 'link'].includes(name)) continue;
    const ref = name === 'img' ? attributes.src : attributes.href;
    if (!ref) {
      errors.push(`${relative(repo, page)}: ${name} has no ${name === 'img' ? 'src' : 'href'}`);
      continue;
    }
    if (name === 'img') {
      if (!attributes.alt?.trim()) errors.push(`${relative(repo, page)}: image needs nonempty alt text: ${ref}`);
      if (!Number.isSafeInteger(Number(attributes.width)) || Number(attributes.width) <= 0 ||
          !Number.isSafeInteger(Number(attributes.height)) || Number(attributes.height) <= 0) {
        errors.push(`${relative(repo, page)}: image needs positive width and height: ${ref}`);
      }
    }
    refs.push({ page, name, ref });
  }
}

for (const { page, name, ref } of refs) {
  let url;
  try {
    const pageUrl = new URL(relative(site, page).split(sep).join('/'), `${origin}/`);
    url = new URL(ref, pageUrl);
  } catch {
    errors.push(`${relative(repo, page)}: invalid URL ${ref}`);
    continue;
  }
  if (url.origin !== origin) {
    if (name === 'img') errors.push(`${relative(repo, page)}: image must be local: ${ref}`);
    continue;
  }
  const pathname = decodeURIComponent(url.pathname);
  const target = resolve(site, `.${pathname}`);
  const rel = relative(site, target);
  if (rel === '..' || rel.startsWith(`..${sep}`)) {
    errors.push(`${relative(repo, page)}: reference escapes blog/: ${ref}`);
    continue;
  }
  const file = pathname.endsWith('/') ? join(target, 'index.html') : target;
  let info;
  try {
    info = statSync(file);
  } catch {
    errors.push(`${relative(repo, page)}: missing local file ${ref}`);
    continue;
  }
  if (!info.isFile()) errors.push(`${relative(repo, page)}: reference is not a file: ${ref}`);
  if (name === 'img' && extname(file) === '.webp' && info.size > 300_000) {
    errors.push(`${relative(repo, page)}: WebP exceeds 300 KB: ${ref}`);
  }
  if (url.hash && idsByPage.has(file) && !idsByPage.get(file).has(decodeURIComponent(url.hash.slice(1)))) {
    errors.push(`${relative(repo, page)}: missing anchor ${ref}`);
  }
}

const cname = readFileSync(resolve(site, 'CNAME'), 'utf8').trim();
if (cname !== 'hydir.wiki') errors.push(`blog/CNAME must contain only hydir.wiki, found: ${cname}`);

if (errors.length) {
  for (const error of errors) console.error(error);
  process.exitCode = 1;
} else {
  console.log(`Blog checks passed: ${pages.length} HTML page(s), ${refs.length} links and assets.`);
}
