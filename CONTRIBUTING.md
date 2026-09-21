# Blog contributions

The site at [hydir.wiki](https://hydir.wiki/) is the static HTML in `blog/`. GitHub Pages publishes every successful update to `main`; deployments use GitHub Actions and do not depend on the commit author's access to a separate hosting account.

1. Create a branch from the current `main`.
2. Edit files under `blog/`. Keep claims tied to the implementation or recorded tests. Use real, cropped screenshots; optimize images for the web and provide descriptive alt text and dimensions.
3. Run `npm ci --ignore-scripts` and `npm run check:blog` from the repository root.
4. Open a pull request to `main`. Wait for **Validate blog** and request review from the blog code owner.
5. Merge after the check and review pass. The **Deploy blog** workflow validates the merged tree again and publishes it to `hydir.wiki`.

The production deployment contains only `blog/`. The workflow needs no repository secret. Do not edit `blog/CNAME` or the `github-pages` environment unless the site domain is intentionally changing. After a merge, verify the Pages deployment and the affected production URLs.
