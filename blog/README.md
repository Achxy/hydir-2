# HydIR blog

The site is static. The article index is `/blogs` and all three posts live under `/articles/`. The P-code guide and the mathematics and compiler-theory articles use the same LaTeX.css fonts, shared styles, navigation, footer, light/dark themes, and reading width.

The articles are authored in `content/` as Markdown. The two theory articles also use inline `$...$` and display `$$...$$` LaTeX; display blocks can have a stable anchor, for example `$$ {#signed-comparison}`. `posts.json` holds metadata. The renderer owns these article pages and their draft-URL redirects; it never replaces the shared blog index.

~~~sh
# From the repository root:
npm ci --ignore-scripts
npm run render:blog
npm run check:blog
python3 scripts/check-wiki-site.py
npm run build:blog
python3 scripts/serve-wiki-site.py --port 4173
~~~

The renderer uses the existing vendored KaTeX 0.16.25 to produce HTML and MathML with strict parsing and no trusted HTML commands. It reuses `vendor/katex/` and its fonts; no additional math runtime or font copy is needed. Article text and equations work without JavaScript or a CDN. `assets/theory.js` powers optional flag, parallel-copy, register-byte, P-code stepping, memory-load, and SSA examples. `assets/theory.css` styles only the equations, diagrams, and examples; the shared stylesheets own page typography and layout.

Generated pages are checked in alongside their Markdown sources. `npm run check:blog` rejects stale generated output or malformed mathematics, validates HTML, and checks site links and fragment targets. The Python checker verifies canonical routes, the sitemap, and local assets. The existing Pages build packages the full site, including clean article routes.

The mathematics and compiler-theory articles checked implementation claims against revision `b00835d7568801738a2ee01e42f6bd11ae537e81`. The P-code guide checks its concrete example and brief HydIR section against revision `34dbb5b11d71e43feb10e8e83e87f307b92012eb`. Source citations are pinned to those revisions. The articles distinguish implementation evidence from proof obligations.

`examples/signed-branch.smt2` is a standalone bitvector identity check. `examples/arithmetic-identities.smt2` contains six additional checks of carry, overflow, borrow, signed comparison, and sign-bit biasing. Z3 4.16.0 returned `unsat` for all seven queries. These queries do not execute or certify HydIR.

Building the site does not push, deploy, or change DNS.
