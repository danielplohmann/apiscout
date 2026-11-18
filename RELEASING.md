# Releasing ApiScout

This repository follows the release process shared across the projects around it
([smda](https://github.com/danielplohmann/smda), [purepdb](https://github.com/danielplohmann/purepdb),
[mcrit](https://github.com/familiary/mcrit) and the rest of the MCRIT ecosystem). The shape is the same
everywhere; this file states the values that are specific to this repository.

## Versioning

ApiScout follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) from 3.0.0 on; see
the note at the top of `CHANGELOG.md` for what that covers and what it does not.

The version is declared in `pyproject.toml` (`[project].version`) and nowhere else: `apiscout --version`
reads it from the installed metadata. The release workflow refuses a tag that does not match it.
`uv.lock` records the version too, and CI installs with `uv sync --locked`, so a bump without
`uv lock` fails CI before it gets anywhere near a tag.

## Supported Python versions

ApiScout supports Python 3.10 and newer, and CI tests 3.10 through 3.15. The DB builder needs the same
3.10; for a system that has no such Python (Windows 7), build the DB from a copy of its DLLs on
another system (`--os_name`, `--os_version`, `--load_addresses`).

The places that state the floor are `requires-python`, which ruff also takes its target version
from, and the `ci.yml` matrix. The release that raises it says so in its `Removed` section, and the one before it carries a
`Deprecated` notice.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). It is the one
authoritative record of what a release contains: the GitHub release notes are generated from it, and
nothing is written twice.

- Every pull request that changes something a user can observe adds its own bullet under
  `## [Unreleased]`, in the subsection it belongs to (`Added`, `Changed`, `Deprecated`, `Removed`,
  `Fixed`, `Security`), while the change is fresh. The `Changelog` check fails a PR that touches
  `apiscout/` or `pyproject.toml` without touching `CHANGELOG.md`; apply the `no-changelog` label when
  a change genuinely needs no entry (a typo, a CI-only change), and say why in the PR.
- An entry says what changed and what it costs the reader: what to do when upgrading, what may
  behave differently, which issue or PR it closes.
- `.gitattributes` merges `CHANGELOG.md` with `merge=union`. Every open pull request appends to the
  same `[Unreleased]` section, so without it the PRs of a stack conflict with each other rather than
  with `master`. Union keeps both sides' lines, which is safe because entries are only appended,
  never edited in place.
- Dependency bumps need no entry. GitHub lists them under their own heading in the release notes,
  from the `dependencies` / `github_actions` labels (`.github/release.yml`).
- A new example DB under `dbs/` is a user-visible change and gets an entry, with `dbs/SHA256SUMS`
  updated in the same PR: `apiscout dbs download` checks every file against it.

## Cutting a release

1. Check that `master` is green and that everything meant for the release has merged.
2. In one commit on a branch, then merged through a PR:
   - set the new version in `pyproject.toml` (`[project].version`) and run `uv lock`;
   - in `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, drop the empty
     subsections, open a fresh `## [Unreleased]` above it, and update the compare links at the foot
     of the file.
3. Wait for CI to pass on the merge commit. Then tag that commit and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "ApiScout X.Y.Z"
   git push origin vX.Y.Z
   ```

Pushing the tag is the release. `.github/workflows/publish-release.yml` then:

1. **Verify** — refuses to continue unless the tag matches the version in `pyproject.toml`,
   `CHANGELOG.md` has a `## [X.Y.Z] - <date>` section (which becomes the release notes), the tagged
   commit is on `master`, CI passed on that commit, and the milestone named for the tag, if there is
   one, has no open items.
2. **Build** — builds the sdist and wheel in an isolated environment with the `release` dependency
   group, checks their metadata with `twine check --strict`, and installs the wheel into a clean
   virtual environment to import it, check the installed version and the shipped package data, and
   run `apiscout --version`.
3. **Publish** — uploads to PyPI through [trusted publishing](https://docs.pypi.org/trusted-publishers/)
   with signed provenance attestations. No API token is stored anywhere.
4. **Release** — creates the GitHub release for the tag with the changelog section as its body,
   GitHub's generated contributor and PR list appended under it, and the sdist and wheel attached;
   then closes the milestone.

A milestone is optional: name one `vX.Y.Z`, exactly as the tag is written, to have the gate see it.

Each gate fails with a message naming what to fix. Nothing has to be remembered at the console.

The example DBs under `dbs/` are not in the wheel. `apiscout dbs download` fetches them from the
repository at the tag of the installed version, so a release makes the DBs of its tag downloadable;
a DB added after a tag reaches users with the next release.

## Pre-releases

A release candidate is tagged `vX.Y.Zrc1` (also `a1`, `b1`), with the same version string in
`pyproject.toml` and a `## [X.Y.Zrc1] - YYYY-MM-DD` changelog section. The workflow marks the GitHub
release as a pre-release and does not make it "latest". PyPI does not install a pre-release unless it
is asked for explicitly (`pip install --pre`).

## Rehearsing

Run *Publish release* manually from the Actions tab, choosing a tag as the ref. A manual run goes
through the same gates and build, publishes to [TestPyPI](https://test.pypi.org/p/apiscout) instead
of PyPI (an already-present version is skipped rather than failed), and stops before creating the
GitHub release. Rehearse the first release after any change to the workflow.

A rehearsal and the real release can both be in flight on one tag, which is how to rehearse a version
before it goes out. Pushing the tag starts the real run, and a required reviewer on the `pypi`
environment holds it at the publish job; rehearse from the same tag while it waits, then approve it,
or reject it and leave the version number unused. The workflow's concurrency group carries the
trigger as well as the ref so that the rehearsal does not queue behind the parked run.

## When a release fails

- **A gate failed before anything was published** (tag/version mismatch, missing changelog section,
  tag not on `master`, CI not green): fix the cause on `master`, delete the tag locally and on the
  remote (`git push --delete origin vX.Y.Z`), and tag again once the fix has merged. Nothing needs
  cleaning up.
- **Publishing to PyPI failed part-way**: a version number on PyPI is permanent even when yanked, so
  do not try to reuse it. Fix the cause, bump the patch version, and release again. Yank the
  incomplete version on PyPI if any of its files were accepted.
- **The GitHub release step failed after publishing**: re-run only the failed job from the Actions
  UI; the built artifacts are kept as workflow artifacts and the step is idempotent.

## Maintainer configuration

Done once, by a repository owner; the workflow cannot create these for itself.

- **PyPI trusted publisher** for the `apiscout` project: owner `danielplohmann`, repository
  `apiscout`, workflow `publish-release.yml`, environment `pypi`. The project exists on PyPI (up to
  2.0.2, uploaded by hand), so this is added under its own Publishing settings.
- **TestPyPI trusted publisher**, the same four values with environment `testpypi`, to enable
  rehearsals. `apiscout` does not exist on TestPyPI, so this one is added as a *pending* publisher
  (Your projects → Publishing → add a pending publisher); the first rehearsal that uploads creates the
  project. A rehearsal is the only thing that publishes to TestPyPI — pushing a tag always goes to
  PyPI.
- **GitHub environments** `pypi` and `testpypi` (Settings → Environments). Restricting `pypi` to the
  `v*` tag pattern and requiring a reviewer is recommended: it makes the publish step a deliberate
  click even if a tag is pushed by mistake.
- **Label** `no-changelog`, used by the changelog check.
- Optionally, **immutable releases** (Settings → General → Releases), so a published release's
  assets and tag can no longer be changed.

## Releases before 3.0.0

Versions up to 2.0.2 were uploaded to PyPI by hand and never tagged, and the changelog lists them in
its older format under *Releases before 3.0.0*. v3.0.0 is the first tag and the first release made
by this workflow.
