export function wikiNavigation(current = '/') {
  const links = [['/', 'Home'], ['/blogs', 'Articles'], ['/guides', 'Docs'], ['/tools', 'Tools'], ['/features', 'Features']];
  return '<header class="site-header"><a class="brand" href="/" aria-label="HydIR home"><img src="/assets/hydir-logo.jpg" width="112" height="112" alt="HydIR dragon logo"><span>HydIR</span></a><nav class="site-nav" aria-label="Main navigation">' + links.map(([href, label]) => `<a href="${href}"${href === current ? ' aria-current="page"' : ''}>${label}</a>`).join('') + '</nav><button class="theme-toggle" type="button" data-theme-toggle aria-pressed="false">Dark mode</button></header>';
}
