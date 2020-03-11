# Release Checklist

- Make sure all changes to be released are on `master`
- Compare `master`'s commit history to the change log to ensure all public API changes are included as well as notable internal changes
- Sanity check the version number set in `Cargo.toml` with the change log. Remember, we use semver!
- Commit `Cargo.toml` (if needed) and `CHANGELOG.md` to your local git.
  - paste change log for the release into the commit message (For Github releases)
- `cargo package` to see if there are any issues
- Tag the release, using the changelog entry as the commit message
  - `git tag -a <NEW_VER_NUM>`
  - `git push origin <NEW_VER_NUM> && git push` (eg: 0.5.2)
- `cargo publish`
- Check crates.io and docs.rs sites for new version
