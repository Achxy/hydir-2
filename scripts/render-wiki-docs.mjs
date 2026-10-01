import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import MarkdownIt from 'markdown-it';
import { wikiNavigation } from './wiki-navigation.mjs';
import { explainers } from './wiki-explainers.mjs';

const repo = fileURLToPath(new URL('../', import.meta.url));
const site = path.join(repo, 'blog');
const docs = JSON.parse(fs.readFileSync(path.join(site, 'docs.json'), 'utf8'));
const checking = process.argv.includes('--check');
const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const sourceUrl = file => 'https://github.com/Achxy/hydir-2/blob/main/' + file.split('/').map(encodeURIComponent).join('/');
const md = new MarkdownIt({ html: false, linkify: false });
// Long source references use topic anchors without changing their technical text.
const sections = {
  'python-sdk': [
    ['For local Ghidra-backed lifting', 'Local worker and snapshot artifacts'],
    ['`LocalGhidra.llvm_cfg(binary, snapshot, process=True)`', 'Process bytes and declared allocations'],
    ['`LocalGhidra.rediscover_calls', 'Observed targets and path comparisons']
  ]
};

// Repository references keep their original source context. Dedicated wiki pages
// replace matching document links while source anchors remain on GitHub.
function resolveLink(ref, source) {
  if (ref.startsWith('/')) return ref;
  if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(ref)) return ref;
  const [file, fragment] = ref.split('#');
  if (!file) return sourceUrl(source) + '#' + fragment;
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(source), file));
  const local = docs.find(doc => doc.source === resolved && !doc.start);
  return local && !fragment ? '/docs/' + local.slug : sourceUrl(resolved) + (fragment ? '#' + fragment : '');
}
const defaultLink = md.renderer.rules.link_open || ((tokens, i, opts, env, self) => self.renderToken(tokens, i, opts));
md.renderer.rules.link_open = (tokens, i, opts, env, self) => {
  tokens[i].attrSet('href', resolveLink(tokens[i].attrGet('href'), env.source));
  return defaultLink(tokens, i, opts, env, self);
};
md.renderer.rules.image = (tokens, i) => `<span>${escape(tokens[i].content || 'Source image')}</span>`;
md.renderer.rules.table_open = () => '<div class="table-scroll" tabindex="0" aria-label="Scrollable reference table"><table>\n';
md.renderer.rules.table_close = () => '</table></div>\n';
md.core.ruler.push('doc-headings', state => {
  const used = new Map();
  state.env.headings = [];
  for (let i = 0; i < state.tokens.length; i++) {
    const token = state.tokens[i];
    if (token.type !== 'heading_open') continue;
    const title = state.tokens[i + 1].content;
    const base = title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'section';
    const count = used.get(base) || 0;
    used.set(base, count + 1);
    const id = base + (count ? '-' + count : '');
    token.attrSet('id', id);
    if (token.tag === 'h2') state.env.headings.push({ id, title });
  }
});

for (const doc of docs) {
  const original = fs.readFileSync(path.join(repo, doc.source), 'utf8').replace(/\r\n/g, '\n');
  let content = original;
  if (doc.start) {
    const start = content.indexOf(doc.start);
    const end = content.indexOf(doc.end, start);
    if (start < 0 || end < 0) throw new Error('Missing document section: ' + doc.slug);
    content = content.slice(start, end).replace(/^## /, '# ').replace(/^### /gm, '## ');
  }
  for (const [prefix, heading] of sections[doc.slug] || []) {
    if (!content.includes(prefix)) throw new Error('Missing topic boundary: ' + doc.slug + ': ' + prefix);
    content = content.replace(prefix, '\n\n## ' + heading + '\n\n' + prefix);
  }
  if (doc.slug === 'native-analysis') content = content.replace(/```mermaid[\s\S]*?```/g, '');
  const env = { source: doc.source };
  let rendered = md.render(content, env);
  const heading = rendered.match(/<h1\b[^>]*>.*?<\/h1>/)?.[0];
  if (!heading) throw new Error('Missing document heading: ' + doc.slug);
  rendered = rendered.replace(heading, '');
  const explainer = explainers[doc.slug] || '';
  const explainerHeading = explainer.match(/<section id="([^"]+)"><h2>([^<]+)<\/h2>/);
  if (explainerHeading) env.headings.unshift({ id: explainerHeading[1], title: explainerHeading[2] });
  const digest = createHash('sha256').update(original).digest('hex').slice(0, 12);
  const toc = env.headings.length ? '<nav class="doc-toc" aria-label="On this page"><p><strong>On this page</strong></p><ul>' + env.headings.map(h => `<li><a href="#${h.id}">${escape(h.title)}</a></li>`).join('') + '</ul></nav>' : '';
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="${escape(doc.description)}">
<link rel="canonical" href="https://hydir.wiki/docs/${doc.slug}">
<link rel="stylesheet" href="/vendor/latex.css/style.css">
<link rel="stylesheet" href="/styles.css">
<script src="/assets/theme.js"></script>
<title>${escape(doc.title)} — HydIR</title>
</head>
<body>
<a class="skip" href="#content">Skip to content</a>
${wikiNavigation('/guides')}
<main class="site-main prose" id="content">
<p class="eyebrow"><a href="/guides">Docs</a> / ${escape(doc.title)}</p>
${heading}
<p class="doc-source">Repository reference · <a href="${sourceUrl(doc.source)}">${escape(doc.source)}</a> · source digest <code>${digest}</code></p>
<p>${escape(doc.description)}</p>
${toc}
${explainer}
${rendered}
<hr>
<h2>Related documentation</h2>
<ul>${docs.filter(other => other.slug !== doc.slug).map(other => `<li><a href="/docs/${other.slug}">${escape(other.title)}</a></li>`).join('')}</ul>
</main>
<footer class="site-footer"><p><a href="https://github.com/Achxy/hydir-2">GitHub</a> · <a href="/#maintainers">Maintainers</a> · <a href="/guides">Documentation index</a> · <a href="/research">Evidence and release gates</a> · <a href="${sourceUrl(doc.source)}">Edit the source on GitHub</a></p></footer>
</body>
</html>
`;
  const output = path.join(site, 'docs', doc.slug + '.html');
  if (checking) {
    if (!fs.existsSync(output) || fs.readFileSync(output, 'utf8') !== html) throw new Error('Stale wiki documentation: ' + doc.slug);
  } else {
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, html);
  }
}
console.log(`${checking ? 'Checked' : 'Rendered'} ${docs.length} repository-backed technical references.`);
