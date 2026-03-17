# SBOM Tool

SBOM Tool generates SBOM files and runs vulnerability checks for the currently opened workspace.

## Dashboard (Activity Bar)

After installation, an SBOM Tool icon appears in the Activity Bar.
From the Dashboard you can:

- Check the currently opened project
- Switch vulnerability scanner (`auto` / `trivy` / `npm-audit`)
- Switch UI language (`auto` / `en` / `ja`)
- Switch result open mode (`vscode` / `external`)
- Run SBOM generation and vulnerability scan actions

## Commands

- `SBOM Tool: Generate SBOM`
- `SBOM Tool: Scan Vulnerabilities`
- `SBOM Tool: Generate SBOM + Scan Vulnerabilities`
- `SBOM Tool: Check Current Project`
- `SBOM Tool: Select Scanner`
- `SBOM Tool: Select UI Language`
- `SBOM Tool: Select Result Open Mode`

## Output

By default, output files are generated under `.sbom-tool/` in your workspace.

- `sbom-raw-*.json`: Internal parsed SBOM data
- `sbom-cyclonedx-*.json` or `sbom-spdx-*.spdx`: Exported SBOM
- `vulnerability-report-*.json`: Vulnerability scan result

## Settings

- `sbomTool.outputDirectory` (default: `.sbom-tool`)
- `sbomTool.defaultSbomFormat` (default: `cyclonedx-json`)
  - `cyclonedx-json`
  - `spdx`
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

- Node.js / npm
- Trivy installed (when using `trivy` mode)

## Language Support

- Default language: English
- Supported language: Japanese (when VS Code display language is `ja`)

## Package

```bash
cd vscode-extension/csap-sbom-security
npm install
npx @vscode/vsce package --allow-missing-repository --skip-license
```

## License

Apache License 2.0
