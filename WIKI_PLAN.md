# HydIR wiki direction

Reference: https://v8.dev/

## Layout

- Keep the homepage text-first: short project introduction, dated article index,
  and direct documentation links. No GUI hero screenshot.
- Retain the blue navigation header, white reading surface in light mode, and
  charcoal surface with yellow links in dark mode.
- Use compact spacing, readable code blocks, numbered figures, and restrained
  diagrams that explain specific operations or implementation boundaries.
- Consolidate the layered stylesheet into one set of component rules in a
  future layout pass, with before/after screenshots at desktop and mobile widths.

## Documentation

- Keep guides on the site, with source citations for implementation details.
- Expand each workflow with prerequisites, runnable examples, output contracts,
  failure cases, and explicit limits. Prioritize end-to-end Ghidra, Frida,
  typed-model, replay, and transformation walkthroughs.
- Keep reference pages distinct from articles: references describe interfaces;
  articles develop one technical question with worked examples and diagrams.
- Check claims against code and fixtures before describing a feature as available.

## Validation completed for this pass

- Generated-source freshness, HTML validation, and 951 local references passed
  across 27 HTML pages; route/font/sitemap checks passed.
- All 24 public routes rendered in the browser without broken images or page-wide
  overflow, including at a 375px viewport.
- All 40 unique local HTTP routes/assets returned 200.
- Light/dark toggle and preference persistence, SDK memory toggle, register
  zero-extension, branch inputs, operation stepping, unknown-memory load, SSA
  predecessor selection, arithmetic flags, and parallel-copy controls checked.
- No browser console errors recorded during the route sweep. Production build passed.

External destinations and executable snippets were not run by this site audit.
Deployment should receive a separate live smoke check after Pages completes.
