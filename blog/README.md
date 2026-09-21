# HydIR blog

The site is static. The article index is `/blogs` and all seven posts live under `/articles/`. The two mathematics and compiler-theory articles use the same LaTeX.css fonts, shared styles, navigation, footer, light/dark themes, and reading width as the existing posts.

The two theory articles are authored in `content/` as Markdown with inline `$...$` and display `$$...$$` LaTeX. Display blocks can have a stable anchor, for example `$$ {#signed-comparison}`. `posts.json` holds their metadata. The renderer owns only those two article pages and their draft-URL redirects; it never replaces the shared blog index.

~~~sh
# From the repository root:
npm ci --ignore-scripts
npm run render:blog
npm run check:blog
python3 scripts/check-wiki-site.py
npm run build:blog
python3 scripts/serve-wiki-site.py --port 4173
~~~

The renderer uses the existing vendored KaTeX 0.16.25 to produce HTML and MathML with strict parsing and no trusted HTML commands. It reuses `vendor/katex/` and its fonts; no additional math runtime or font copy is needed. Article text and equations work without JavaScript or a CDN. `assets/theory.js` powers optional flag and parallel-copy examples. `assets/theory.css` styles only the equations, diagram, and examples; the shared stylesheets own page typography and layout.

Generated pages are checked in alongside their Markdown sources. `npm run check:blog` rejects stale generated output or malformed mathematics, validates HTML, and checks site links and fragment targets. The Python checker verifies canonical routes, the sitemap, and local assets. The existing Pages build packages the full site, including clean article routes.

Implementation claims were checked against revision `b00835d7568801738a2ee01e42f6bd11ae537e81`, and repository citations are pinned to it. The articles distinguish the native compiler pipeline from the scalar LLVM compatibility path, and mathematical derivations from implementation evidence and proof obligations.

`examples/signed-branch.smt2` is a standalone bitvector identity check. `examples/arithmetic-identities.smt2` contains six additional checks of carry, overflow, borrow, signed comparison, and sign-bit biasing. Z3 4.16.0 returned `unsat` for all seven queries. These queries do not execute or certify HydIR.

Building the site does not push, deploy, or change DNS.
