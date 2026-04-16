# Release

- Make sure all changes to be released are on `main`
- Compare `main`'s commit history to the changelog to ensure all public API changes are included as well as notable internal changes
  - If necessary, PR and merge the changelog changes.
- Run the [Bump Version](.github/workflows/bump-version.yaml) workflow.
  - Give it a new release version. For example, if the current version is 1.2.3-pre.4, type in 1.2.3. This will cause a release to [crates.io](https://crates.io/crates/recrypt).
