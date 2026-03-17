# Publishing SBOM Tool to VS Code Marketplace

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
- Search `SBOM Tool`
- Confirm install works and update channel is enabled

## 5) Local VSIX release (optional)

For GitHub/manual distribution:

```bash
npm run release:patch
```

Generated files:
- `releases/sbom-tool-latest.vsix`
- `releases/sbom-tool-<version>.vsix`
