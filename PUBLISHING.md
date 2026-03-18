# Publishing SBOM Vulnerability Scanner to VS Code Marketplace

## 1) Prerequisites

- Microsoft publisher account for `masahirocom`
- Azure DevOps Personal Access Token (PAT) with Marketplace `Manage` scope
- Node.js / npm

## 2) Login for publishing

```bash
cd vscode-extension/csap-sbom-security
npx @vscode/vsce login masahirocom
```

When prompted, paste your PAT.

## 3) Publish with version bump

Patch release (recommended default):

```bash
npm run publish:patch
```

Or publish with current version in `package.json`:

```bash
npm run publish:marketplace
```

## 4) Validate published extension

- Open VS Code Extensions view
- Search `SBOM Vulnerability Scanner`
- Confirm install works and update channel is enabled

## 5) Local VSIX release (optional)

For GitHub/manual distribution:

```bash
npm run release:patch
```

Generated files:
- `releases/sbom-vulnerability-scanner-latest.vsix`
- `releases/sbom-vulnerability-scanner-<version>.vsix`

## 6) Automatic VSIX build on release push

When you push a release tag (for example `v0.1.7`), GitHub Actions automatically:

- builds the VSIX
- uploads it as workflow artifacts
- attaches the VSIX files to the GitHub Release for that tag

Example:

```bash
git tag -a v0.1.7 -m "Release v0.1.7"
git push origin v0.1.7
```
