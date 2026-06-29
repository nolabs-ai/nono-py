# Release Process

Releases are reviewed through pull requests. A maintainer should not push a
release tag or create a GitHub release by hand for a normal release.

## Normal Release

1. Create a branch for the release bump.
2. Bump the version in all three files:
   - `pyproject.toml`
   - `Cargo.toml`
   - `python/nono_py/__init__.py`
3. Open a pull request, for example `chore(release): bump version to 0.11.0`.
4. Wait for CI and review.
5. Merge the pull request to `main`.
6. Watch the `Auto-release on version bump` workflow.

The workflow publishes to PyPI first. Only after PyPI publish succeeds does it
create the `vX.Y.Z` git tag and the GitHub release.

## Do Not

- Do not push `vX.Y.Z` manually.
- Do not create the GitHub release manually.
- Do not run the PyPI publish workflow against an arbitrary tag or branch.
- Do not merge a release PR unless the three version files match.

## Trusted Publishing

PyPI Trusted Publishing must be configured for:

```text
.github/workflows/auto-release.yml
```

The PyPI upload step intentionally lives directly inside that workflow. Do not
move publishing behind a reusable workflow; PyPI validates the exact workflow
path that requests the OIDC token.

## Recovery

If the workflow fails before PyPI upload, fix the problem in a PR and merge it.

If PyPI upload succeeds but tag or GitHub release creation fails, rerun
`Auto-release on version bump` manually from `main`. The workflow checks PyPI,
tags, and GitHub releases before acting, so it will skip the already-published
PyPI version and create only the missing outputs.

If a version was published to PyPI with the wrong files, do not reuse that
version. PyPI does not allow replacing files for an existing release. Bump to
the next patch version and release through the normal PR process.
