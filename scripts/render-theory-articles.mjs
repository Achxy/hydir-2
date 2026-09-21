import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import MarkdownIt from 'markdown-it';

const site = fileURLToPath(new URL('../blog/', import.meta.url));
const require = createRequire(import.meta.url);
// Use the exact same renderer and fonts as the existing mathematics article.
const katex = require('../blog/vendor/katex/katex.min.js');
const checking = process.argv.includes('--check');
const posts = JSON.parse(fs.readFileSync(path.join(site, 'posts.json'), 'utf8'));
const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const slugify = value => value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

function math(tex, displayMode) {
  const rendered = katex.renderToString(tex, {
    displayMode, throwOnError: true, strict: 'error', trust: false,
    output: 'htmlAndMathml',
    macros: { '\\BV': '\\mathbb{B}', '\\msb': '\\operatorname{msb}', '\\Obs': '\\operatorname{Obs}' }
  });
  // KaTeX computes glyph positioning as inline styles. Keep this exception
  // restricted to renderer-owned math; authored HTML remains fully validated.
  return '<!-- html-validate-disable no-inline-style -->' + rendered +
    '<!-- html-validate-enable no-inline-style -->';
}

function parser() {
  const md = new MarkdownIt({ html: true, typographer: false });
  md.inline.ruler.before('escape', 'math_inline', (state, silent) => {
    const start = state.pos;
    if (state.src[start] !== '$' || state.src[start + 1] === '$') return false;
    let end = start + 1;
    while ((end = state.src.indexOf('$', end)) !== -1) {
      if (state.src[end - 1] !== '\\') break;
      end++;
    }
    if (end === -1 || end === start + 1) return false;
    if (!silent) {
      const token = state.push('math_inline', 'math', 0);
      token.content = state.src.slice(start + 1, end);
    }
    state.pos = end + 1;
    return true;
  });
  md.block.ruler.before('fence', 'math_block', (state, start, end, silent) => {
    const line = state.src.slice(state.bMarks[start] + state.tShift[start], state.eMarks[start]);
    const match = /^\$\$(?:\s+\{#([a-z][a-z0-9-]*)\})?\s*$/.exec(line);
    if (!match) return false;
    let close = start + 1;
    for (; close < end; close++) {
      if (state.src.slice(state.bMarks[close], state.eMarks[close]).trim() === '$$') break;
    }
    if (close === end) throw new Error('Unclosed display math at line ' + (start + 1));
    if (silent) return true;
    const token = state.push('math_block', 'math', 0);
    token.content = state.getLines(start + 1, close, 0, false).trim();
    token.meta = { id: match[1] };
    token.map = [start, close + 1];
    state.line = close + 1;
    return true;
  }, { alt: ['paragraph', 'reference', 'blockquote', 'list'] });
  md.renderer.rules.math_inline = (tokens, i, options, env) => {
    env.inlineMath++;
    return math(tokens[i].content, false);
  };
  md.renderer.rules.math_block = (tokens, i, options, env) => {
    const number = ++env.equations;
    const id = tokens[i].meta.id || 'equation-' + number;
    return '<div class="equation" id="' + id + '"><section class="equation-scroll" tabindex="0" aria-label="Equation ' +
      number + '">' + math(tokens[i].content, true) + '</section><a class="equation-number" href="#' +
      id + '" aria-label="Link to equation ' + number + '">(' + number +
      ')</a><span class="equation-hint" hidden aria-hidden="true">Scroll equation →</span></div>\n';
  };
  md.renderer.rules.fence = (tokens, i) => {
    const token = tokens[i];
    return '<pre tabindex="0"><code class="language-' + escape(token.info.trim() || 'text') +
      '">' + escape(token.content) + '</code></pre>\n';
  };
  md.renderer.rules.table_open = (tokens, i, options, env) =>
    '<section class="table-scroll" tabindex="0" aria-label="Table ' + (++env.tables) + '"><table>\n';
  md.renderer.rules.table_close = () => '</table></section>\n';
  md.core.ruler.push('headings', state => {
    for (let i = 0; i < state.tokens.length; i++) {
      const token = state.tokens[i];
      if (token.type === 'heading_open') token.attrSet('id', slugify(state.tokens[i + 1].content));
    }
  });
  return md;
}

function head(post, redirect = false) {
  const route = '/articles/' + post.slug;
  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n' +
    '  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '  <meta name="description" content="' + escape(post.description) + '">\n' +
    '  <link rel="canonical" href="https://hydir.wiki' + route + '">\n' +
    (redirect ? '  <meta http-equiv="refresh" content="0;url=' + route + '">\n' : '') +
    '  <link rel="stylesheet" href="/vendor/latex.css/style.css">\n' +
    '  <link rel="stylesheet" href="/vendor/katex/katex.min.css">\n' +
    '  <link rel="stylesheet" href="/styles.css">\n' +
    '  <link rel="stylesheet" href="/assets/theory.css">\n' +
    '  <title>' + escape(post.title + ': ' + post.subtitle) + ' — HydIR</title>\n</head>\n';
}

const nav = '  <a class="skip" href="#article">Skip to article</a>\n' +
  '  <header class="site-header"><a class="brand" href="/">HydIR</a><nav class="site-nav" aria-label="Main navigation">' +
  '<a href="/">Home</a><a href="/start">Start</a><a href="/architecture">Architecture</a>' +
  '<a href="/blogs" aria-current="page">Blogs</a></nav></header>\n';
const footer = '  <footer class="site-footer"><p><a href="/">HydIR</a> · ' +
  '<a href="https://github.com/Achxy/hydir-2">Source</a> · <a href="/start">Start locally</a></p></footer>\n';

function output(name, html) {
  const target = path.join(site, name);
  if (checking) {
    if (!fs.existsSync(target) || fs.readFileSync(target, 'utf8') !== html) {
      throw new Error(name + ' is missing or stale; run npm run render:blog.');
    }
  } else {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, html);
  }
}

for (const post of posts) {
  const source = fs.readFileSync(path.join(site, 'content', post.slug + '.md'), 'utf8');
  const env = { equations: 0, inlineMath: 0, tables: 0 };
  const content = parser().render(source, env);
  const html = head(post) + '<body class="latex-dark-auto">\n' + nav +
    '  <main class="site-main prose" id="article">\n    <article>\n' +
    '      <p class="eyebrow"><a href="/blogs">Blogs</a> / ' + escape(post.category) + '</p>\n' +
    '      <h1>' + escape(post.title + ': ' + post.subtitle) + '</h1>\n' +
    '      <p class="lead">' + escape(post.lead) + '</p>\n' + content +
    '<p class="small muted"><a href="/content/' + post.slug + '.md">Download the Markdown and LaTeX source</a></p>\n' +
    '    </article>\n  </main>\n' + footer +
    '  <script type="module" src="/assets/theory.js"></script>\n</body>\n</html>\n';
  output('articles/' + post.slug + '.html', html);
  // Preserve draft preview bookmarks while keeping one canonical article URL.
  output(post.slug + '.html', head(post, true) + '<body class="latex-dark-auto">\n' + nav +
    '  <main class="site-main prose" id="article"><h1>' + escape(post.title) + '</h1>' +
    '<p>This article is now in <a href="/articles/' + post.slug + '">the HydIR blog</a>.</p></main>\n' +
    footer + '</body>\n</html>\n');
  console.log(post.slug + ': ' + env.equations + ' display equations, ' + env.inlineMath + ' inline expressions');
}
console.log((checking ? 'Checked' : 'Rendered') + ' two articles using the shared HydIR layout and vendored KaTeX.');
