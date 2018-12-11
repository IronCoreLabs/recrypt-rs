Release Checklist
=================

* Decide on the new version number (we use semver)
* Write the CHANGELOG.md entry for the release by looking at the PRs
* Commit `Cargo.toml` (for version number) and `CHANGELOG.md` to your local git
* `cargo package` to see if there are any issues
* `git tag <NEW_VER_NUM> && git push origin <NEW_VER_NUM>` (eg: 0.5.2)
* `cargo publish`