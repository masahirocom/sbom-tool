# SBOM Vulnerability Scanner

**GitHub Repository**: [masahirocom/sbom-vulnerability-scanner](https://github.com/masahirocom/sbom-vulnerability-scanner)

- English: [README.md](README.md)
- 日本語: [README.ja.md](README.ja.md)

SBOM Vulnerability Scanner generates SBOM files and runs vulnerability checks for the currently opened workspace.

## Download VSIX

Use this file for installation:

- [releases/sbom-vulnerability-scanner-latest.vsix](releases/sbom-vulnerability-scanner-latest.vsix)

You can also use a version-pinned file in [releases](releases).
Versioned example: `releases/sbom-vulnerability-scanner-<version>.vsix`

## Install from Marketplace (recommended)

Once published to VS Code Marketplace, install SBOM Vulnerability Scanner from the Extensions view.
Marketplace installations support automatic updates.

## Dashboard (Activity Bar)

After installation, an SBOM Vulnerability Scanner icon appears in the Activity Bar.
From the Dashboard you can:

- Check the currently opened project
- Switch SBOM generator (`auto` / `syft` / `trivy` / `manifest`)
- Switch vulnerability scanner (`auto` / `trivy` / `npm-audit`)
- Switch UI language (`auto` / `en` / `ja`)
- Switch result open mode (`vscode` / `external`)
- Run SBOM generation and vulnerability scan actions

## Commands

- `SBOM Vulnerability Scanner: Generate SBOM`
- `SBOM Vulnerability Scanner: Scan Vulnerabilities`
- `SBOM Vulnerability Scanner: Generate SBOM + Scan Vulnerabilities`
- `SBOM Vulnerability Scanner: Check Current Project`
- `SBOM Vulnerability Scanner: Select Scanner`
- `SBOM Vulnerability Scanner: Select SBOM Generator`
- `SBOM Vulnerability Scanner: Select UI Language`
- `SBOM Vulnerability Scanner: Select Result Open Mode`
- `SBOM Vulnerability Scanner: Set Up Syft and Trivy`

The setup command is explicit and user-driven.
- **macOS/Linux with Homebrew**: runs `brew install syft trivy` in the terminal after user selection
- **Windows with WinGet**: runs `winget install Anchore.syft AquaSecurity.Trivy` in the terminal after user selection
- **Windows with Scoop**: runs `scoop install syft trivy` in the terminal after user selection
- **All platforms**: download binaries from GitHub Releases or open official installation guides for alternative methods

## Output

By default, output files are generated under `.sbom-tool/` in your workspace.

- `sbom-raw-*.json`: Internal parsed SBOM data
- `sbom-cyclonedx-*.json` or `sbom-spdx-*.*`: Exported SBOM
- `sbom-report-*.html`: Human-readable SBOM report
- `vulnerability-report-*.json`: Vulnerability scan result

## Settings

- `sbomTool.outputDirectory` (default: `.sbom-tool`)
- `sbomTool.defaultSbomFormat` (default: `cyclonedx-json`)
  - `cyclonedx-json`
  - `spdx`
- `sbomTool.sbomGenerator` (default: `auto`)
  - `auto`: Tries Syft first, then Trivy, then the built-in manifest parser
  - `syft`: Uses Syft only
  - `trivy`: Uses Trivy only
  - `manifest`: Uses the built-in package manifest parser only
- `sbomTool.vulnerabilityScanner` (default: `auto`)
  - `auto`: Tries Trivy first, falls back to npm audit
  - `trivy`: Uses Trivy only
  - `npm-audit`: Uses npm audit only
- `sbomTool.uiLanguage` (default: `auto`)
  - `auto`: Follows VS Code display language
  - `en`: English
  - `ja`: Japanese
- `sbomTool.resultOpenMode` (default: `vscode`)
  - `vscode`: Opens reports inside VS Code
  - `external`: Opens reports in external browser

## Prerequisites

- Syft installed for the broadest SBOM coverage across languages and package managers
- Trivy installed when using Trivy-based SBOM generation or vulnerability scanning
- Node.js / npm when using the built-in manifest fallback or npm audit

Use the setup command from the dashboard or command palette to choose how to install or review setup instructions.

## Language Support

- Default language: English
- Supported language: Japanese (when VS Code display language is `ja`)

## Package

```bash
cd vscode-extension/csap-sbom-security
npm install
npm run release:patch
```

## Publish (Marketplace)

```bash
cd vscode-extension/csap-sbom-security
npm install
npm run publish:patch
```

See [PUBLISHING.md](PUBLISHING.md) for complete setup (publisher and PAT).

## License

Apache License 2.0
