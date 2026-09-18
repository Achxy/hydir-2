# Blog contributions

The site at [hydir.wiki](https://hydir.wiki/) is the static HTML in `blog/`. The Vercel project uses `blog/` as its root directory. It creates a preview for a branch or pull request and publishes `main` to production; no Vercel token is needed in GitHub Actions.

1. Ask for access to the private GitHub repository, then create a branch from the current `main`.
2. Edit `blog/index.html` and `blog/styles.css`. Keep claims tied to the implementation or recorded tests. Use real, cropped screenshots; optimize images for the web and provide descriptive alt text and dimensions.
3. Run `npm ci` and `npm run check:blog` from the repository root.
4. Open a pull request to `main`. Review the **Validate blog** check and Vercel preview, including a narrow viewport. Request review from the blog code owner.
5. Merge only after the check and review pass. Vercel deploys the merge to `hydir.wiki`; check the production page after deployment.

The CI check validates the HTML and local links/assets. It runs without deployment secrets. Do not use `vercel --prod` for ordinary changes: the Git integration handles production releases. A Vercel Hobby project may restrict previews from some private-repository contributors; if a preview is denied, the project owner must resolve the access requirement before merge.
