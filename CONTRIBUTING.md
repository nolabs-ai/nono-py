# Contributing

When contributing to nono-py, please first discuss the change you wish to make via an issue in the repository.

## Pull Request Process

1. Create an issue outlining the fix or feature.
2. Fork the repository to your own GitHub account and clone it locally.
3. Set up your development environment (see [DEVELOPMENT.md](DEVELOPMENT.md)).
4. Complete and test your change.
5. If relevant, update documentation — this includes type stubs (`_nono_py.pyi`), docstrings, and docs under `docs/`.
6. Format your commit message following the [guidelines below](#commit-message-guidelines).
7. Sign off your commit (see [Developer Certificate of Origin](#developer-certificate-of-origin)).
8. Ensure CI passes. If it fails, fix the failures.
9. Every pull request requires a review from a maintainer.
10. If your pull request consists of more than one commit, please squash your commits as described in [Squash Commits](#squash-commits), or the commits will be squashed on merge.

## Development Setup

```bash
# Clone and set up
git clone https://github.com/always-further/nono-py.git
cd nono-py
uv sync
uv run maturin develop

# Run tests
uv run pytest tests/ -v

# Run linters
cargo fmt --check && cargo clippy -- -D warnings
uv run ruff format --check python/ tests/
uv run ruff check python/ tests/
uv run mypy python/nono_py
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed instructions, including working with a local copy of the nono Rust library.

## Developer Certificate of Origin

All commits must be signed off to indicate you agree to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This certifies that you wrote the contribution or otherwise have the right to submit it.

To sign off, add `-s` to your commit:

```bash
git commit -s -m "Your commit message"
```

This adds a `Signed-off-by` line to your commit message. If you forget, you can amend:

```bash
git commit --amend -s
```

## Commit Message Guidelines

We follow the commit formatting recommendations found on [Chris Beams' How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/).

A good commit message:

```
Summarize changes in around 50 characters or less

More detailed explanatory text, if necessary. Wrap it to about 72
characters or so. Focus on why you are making this change as opposed
to how (the code explains that).

Resolves: #123
```

Note the `Resolves #123` tag — this references the issue and allows us to ensure issues are closed when a pull request is merged.

## Squash Commits

Should your pull request consist of more than one commit (perhaps due to a change being requested during the review cycle), please perform a git squash once a reviewer has approved your pull request.

```bash
# Squash the last 3 commits
git rebase -i HEAD~3
```

Change all but the first commit from `pick` to `squash`, then update the commit message. Force push to your branch:

```bash
git push origin your-branch --force
```

Alternatively, a maintainer can squash your commits within GitHub.

## Code Style

- **Python**: ruff for formatting and linting, mypy for type checking (strict mode), ty as a secondary type checker. Target Python 3.10+, line length 100.
- **Rust**: `cargo fmt` for formatting, `cargo clippy -- -D warnings` for linting. Edition 2021.
- **Type stubs**: `python/nono_py/_nono_py.pyi` must stay in sync with the Rust API. If you change a `#[pyclass]` or `#[pymethods]` block, update the corresponding stub.

## Testing

- All new functionality must have tests.
- Run `uv run pytest tests/ -v` before submitting.
- For Rust changes, run `cargo clippy -- -D warnings` to catch issues early.
