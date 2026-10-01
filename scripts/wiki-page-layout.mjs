const escape = text => text.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
export function polishWikiPage(html, { toc = true, source = 'blog/index.html' } = {}) {
  html = html.replace(/\r\n/g, '\n');
  // Recompute generated navigation; preserve authored section IDs and links.
  html = html.replace(/<!-- page-toc -->[\s\S]*?<!-- \/page-toc -->\s*/g, '');
  const used = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
  const headings = [];
  html = html.replace(/<h2([^>]*)>([\s\S]*?)<\/h2>/g, (_, attrs, inner) => {
    inner = inner.replace(/<a class="heading-anchor"[\s\S]*?<\/a>/g, '');
    const title = inner.replace(/<[^>]+>/g, '').trim();
    let id = /\bid="([^"]+)"/.exec(attrs)?.[1];
    if (!id) {
      const base = title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'section';
      id = base;
      for (let n=2; used.has(id); n++) id = base + '-' + n;
      used.add(id);
      attrs += ` id="${id}"`;
    }
    headings.push([id,title]);
    return `<h2${attrs}>${inner}<a class="heading-anchor" href="#${id}" aria-label="Link to ${escape(title)}">#</a></h2>`;
  });
  const navigation = `<nav class="doc-toc" aria-label="On this page"><p><strong>On this page</strong></p><ul>${headings.map(([id,title])=>`<li><a href="#${id}">${title}</a></li>`).join('')}</ul></nav>`;
  if (toc && headings.length > 2) {
    if (/<nav class="doc-toc"/.test(html)) html = html.replace(/<nav class="doc-toc"[\s\S]*?<\/nav>/, navigation);
    else html = html.replace(/(<p class="lead">[\s\S]*?<\/p>)/, '$1\n<!-- page-toc -->'+navigation+'<!-- /page-toc -->');
  }
  const footer = source === 'blog/index.html' ? `<footer class="site-footer" data-home-footer><div class="footer-copy"><nav class="footer-links" aria-label="Project links"><a href="https://github.com/Achxy/hydir-2">GitHub</a><a href="/#maintainers">Maintainers</a><a href="https://github.com/Achxy/hydir-2/blob/main/CONTRIBUTING.md">Contributing</a><a href="https://github.com/Achxy/hydir-2/blob/main/blog/index.html">Edit this page on GitHub</a><button type="button" class="footer-theme" data-theme-toggle aria-pressed="false">Dark mode</button></nav><p>HydIR is open-source software licensed under the <a href="https://github.com/Achxy/hydir-2/blob/main/LICENSE">GNU Affero General Public License v3.0</a>. See the repository for license notices and contribution guidelines.</p></div><a class="footer-brand" href="/" aria-label="HydIR home"><img src="/assets/hydir-logo.jpg" width="722" height="831" alt="HydIR dragon logo"></a></footer>` : `<footer class="site-footer"><p><a href="/">HydIR</a> · <a href="https://github.com/Achxy/hydir-2">GitHub</a> · <a href="/#maintainers">Maintainers</a> · <a href="https://github.com/Achxy/hydir-2/blob/main/${source}">Edit this page</a> · <a href="https://github.com/Achxy/hydir-2/blob/main/LICENSE">AGPL-3.0-only</a></p></footer>`;
  return html.replace(/<footer class="site-footer">[\s\S]*?<\/footer>/, footer).replace(/[ \t]+$/gm, '');
}
