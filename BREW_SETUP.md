# Homebrew Tap Setup

This document explains how to set up the Homebrew tap for `webdiag` so that users can install it via `brew install mqry/tap/webdiag`.

## Prerequisites

1. A GitHub account with the username `mqry`
2. The `webdiag` repository already exists at `github.com/mqry/webdiag`

## Step 1: Create the Homebrew Tap Repository

Create a new GitHub repository called `homebrew-tap` at `github.com/mqry/homebrew-tap`.

```bash
# Create the repository on GitHub, then clone it
git clone git@github.com:mqry/homebrew-tap.git
cd homebrew-tap
```

The repository should be empty (no README, no .gitignore).

## Step 2: Configure GoReleaser

The `.goreleaser.yaml` file in the `webdiag` repository is already configured with:

```yaml
brews:
  - name: webdiag
    tap:
      owner: mqry
      name: homebrew-tap
    homepage: https://github.com/mqry/webdiag
    description: A fast, lightweight CLI tool for diagnosing websites
    license: MIT
    skip_upload: false
```

This tells GoReleaser to automatically generate and push a Homebrew formula to your tap repository when you create a release.

## Step 3: Set up GitHub Actions

The `.github/workflows/release.yml` workflow is already configured to:

1. Trigger on version tags (e.g., `v1.0.0`)
2. Run GoReleaser with release mode
3. Automatically push the Homebrew formula to your tap repository

## Step 4: Create a Release

When you're ready to release a new version:

```bash
# Tag the release
git tag v1.0.0
git push origin v1.0.0
```

This will trigger the GitHub Actions workflow, which will:

1. Build binaries for multiple platforms
2. Create a GitHub release
3. Generate a Homebrew formula
4. Push the formula to `github.com/mqry/homebrew-tap`

## Step 5: Test the Installation

After the release is complete, users can install `webdiag` via Homebrew:

```bash
brew install mqry/tap/webdiag
```

## Troubleshooting

### GoReleaser fails to push to tap repository

Make sure you have the correct GitHub token permissions:
1. Go to GitHub repository Settings → Secrets and variables → Actions
2. Ensure `GITHUB_TOKEN` has `contents: write` permission (this is set in the workflow file)

### Tap repository doesn't exist

Create the repository at `github.com/mqry/homebrew-tap` before creating the first release.

### Formula not updating

Check the GitHub Actions logs to see if GoReleaser successfully pushed the formula. The formula file should be at `Formula/webdiag.rb` in the tap repository.
