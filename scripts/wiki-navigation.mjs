export function wikiNavigation(current = '/') {
  const links = [['/', 'Home'], ['/blogs', 'Articles'], ['/guides', 'Docs'], ['/tools', 'Tools'], ['/features', 'Features'], ['/research', 'Research']];
  return '<header class="site-header"><a class="brand" href="/" aria-label="HydIR home"><img src="/assets/hydir-placeholder.svg" width="112" height="112" alt="HydIR placeholder monogram"><span>HydIR</span></a><nav class="site-nav" aria-label="Main navigation">' + links.map(([href, label]) => `<a href="${href}"${href === current ? ' aria-current="page"' : ''}>${label}</a>`).join('') + '</nav><p class="rail-caption">Binary analysis<br>and transformation</p><a class="rail-source" href="https://github.com/Achxy/hydir-2">Source on GitHub ↗</a></header>';
}
