# Contributing to HydIR

Thanks for helping improve HydIR. We welcome bug fixes, analysis improvements, tests, integration work, documentation, and reproducible examples.

## Questions and feature ideas

Start with the [README](README.md), [design notes](DESIGN.md), and component documentation. Search [existing issues](https://github.com/Achxy/hydir-2/issues) before opening a new one.

For questions, explain what you are trying to do and where you got stuck. For enhancements, describe the use case, current limitations, proposed behavior, and alternatives you considered. Discuss larger changes in an issue before investing in implementation.

## Reporting bugs

Open a [GitHub issue](https://github.com/Achxy/hydir-2/issues/new) with:

- A clear title and the commit or version you tested.
- Reproduction steps, including exact commands or GUI actions.
- Expected and actual behavior.
- Relevant logs, diagnostics, and screenshots.
- Your OS, architecture, Rust version, and relevant runtime versions.
- A minimal input or fixture you have permission to share.

For analysis errors, include the function or instruction address, relevant artifacts, and bounds or assumptions. Remove credentials, private binaries, and sensitive data from reports.

Report vulnerabilities through GitHub's private vulnerability reporting option in the repository Security tab if available. If unavailable, ask a maintainer for a private channel without publishing vulnerability details.

## Getting started

Fork the repository, clone your fork, and create a branch from the current `main`:

```sh
git clone git@github.com:YOUR_USERNAME/hydir-2.git
cd hydir-2
git switch -c contrib/describe-your-change
```

The Rust toolchain is pinned to **1.96.0** in [rust-toolchain.toml](rust-toolchain.toml). Install Rust through rustup and the compiler and linker required for your platform. Run commands from the repository root unless stated otherwise.

Build the desktop and CLI together so the desktop can find its worker executable:

```sh
cargo build --locked -p hydir-gui -p hydir-cli
cargo run --locked --bin hydirctl -- doctor
```

Optional runtimes depend on your workflow. Ghidra uses a managed container with Docker, or a local installation configured through `HYDIR_GHIDRA_HOME`. Follow the relevant setup instructions:

- [Desktop workbench](crates/hydir-gui/README.md)
- [Ghidra integration](integrations/ghidra/README.md)
- [Frida integration](integrations/frida/README.md)
- [Python SDK](sdk/python/README.md)
- [Fuzzing](fuzz/README.md)

The Python SDK requires Python 3.10 or later. Blog tooling uses Node.js and npm. Initialize submodules when your work needs upstream reference projects:

```sh
git submodule update --init --recursive
```

## Making changes

Keep contributions focused on one problem and follow surrounding code conventions.

| Path | Purpose |
| --- | --- |
| `crates/` | Rust analysis, IR, execution, transformation, CLI, service, and desktop |
| `sdk/python/` | Python client |
| `integrations/` | Ghidra and Frida tooling |
| `tests/` and `fuzz/` | Fixtures, integration checks, and fuzz targets |
| `scripts/` | Validation, demos, packaging, and documentation tooling |
| `blog/` | Static documentation and articles |
| `vendor/` and `third_party/` | Patched dependencies and upstream reference projects |

Preserve explicit bounds, unsupported-operation diagnostics, and evidence provenance. Support changes to semantic claims with reproducible evidence. Distinguish a tested input or bounded path from whole-function equivalence.

Add regression tests for bug fixes when practical. Changes to lifting, execution, or transformation should include fixtures and comparisons that exercise the affected behavior and its limits. Use small, redistributable fixtures with documented origins and assumptions.

Avoid unrelated formatting, generated output, local caches, and dependency updates. Explain changes to vendored code or submodule revisions. Keep API and artifact changes consistent across affected clients and documentation.

Use descriptive commit messages, such as `fix: preserve unresolved jump diagnostics` or `docs: clarify local Ghidra setup`. Explain the reason when it is not obvious from the diff.

## Testing

Run checks for the components you changed. For example, a patch-language change should include:

```sh
cargo test --locked -p hydir-patch
```

Use the same form for other affected crates, including consumers when behavior crosses crate boundaries. The [semantic gate](.github/workflows/semantic-gate.yml) lists CI test groups and native dependencies. Other [workflows](.github/workflows) cover Ghidra, Frida, real ELF comparisons, and fuzzing; follow the relevant workflow when changing those paths.

For Rust formatting, install rustfmt if needed and check the first-party packages you touched:

```sh
rustup component add rustfmt
cargo fmt -p hydir-patch -- --check
```

Replace `hydir-patch` with the affected package. Run without `--check` to apply formatting, then inspect the diff.

Record validation commands and results in your pull request. If you lack a required runtime or platform, state which checks were not run and why.

## Documentation and blog contributions

Update documentation when commands, APIs, requirements, or supported behavior change. Keep examples reproducible and claims tied to implementation or recorded tests. Use real, cropped screenshots with descriptive alt text and dimensions; optimize images for the web.

The site at [hydir.wiki](https://hydir.wiki/) is the static HTML in `blog/`. Some pages are generated: edit their source and regenerate them. See the [blog README](blog/README.md) and renderer scripts referenced in [package.json](package.json).

Run these commands from the repository root:

```sh
npm ci --ignore-scripts
npm run render:blog
npm run check:blog
```

Inspect generated changes before submitting. Open a pull request to `main`, wait for **Validate blog**, and request review from the blog code owner in [CODEOWNERS](.github/CODEOWNERS).

GitHub Pages publishes successful updates to `main`. The **Deploy blog** workflow validates the merged tree again and publishes only `blog/`. Deployments use GitHub Actions and need no repository secret or separate hosting account access from contributors. Do not change `blog/CNAME` or the `github-pages` environment unless the site domain is intentionally changing. After merging, verify the Pages deployment and affected production URLs.

## Pull requests

Open a pull request against `main` with:

- The problem being solved and related issue links.
- The resulting behavior, assumptions, and limitations.
- Validation commands and results, including checks not run.
- Screenshots for visible UI changes or a minimal example for analysis changes.

Keep the diff reviewable and respond to feedback. Merge after relevant checks and review pass. You do not need to join a project team to contribute; a small issue, test, or documentation fix is a good starting point.

## Community and licensing

Be respectful, give constructive feedback, and keep discussions focused on the work. Contributors of all experience levels are welcome.

HydIR uses [AGPL-3.0-only](LICENSE). Submit work you authored or have permission to contribute under that license. Preserve attribution and license notices for third-party material.
