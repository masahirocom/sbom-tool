# CSAP SBOM Security (Internal)

この拡張は、現在開いているワークスペースに対して **SBOM生成** と **脆弱性スキャン** をローカル実行します。

## Commands

- `CSAP SBOM: Generate SBOM`
- `CSAP SBOM: Scan Vulnerabilities`
- `CSAP SBOM: Generate SBOM + Scan Vulnerabilities`

## Output

デフォルトではワークスペース直下の `.csap-sbom/` に出力されます。

- `sbom-raw-*.json` : 解析内部SBOM
- `sbom-cyclonedx-*.json` または `sbom-spdx-*.spdx` : エクスポートSBOM
- `vulnerability-report-*.json` : 脆弱性スキャン結果

## Settings

- `csapSbom.outputDirectory` (default: `.csap-sbom`)
- `csapSbom.defaultSbomFormat` (default: `cyclonedx-json`)
  - `cyclonedx-json`
  - `spdx`
- `csapSbom.vulnerabilityScanner` (default: `auto`)
  - `auto`: Trivy優先、失敗時 npm audit
  - `trivy`: Trivyのみ
  - `npm-audit`: npm auditのみ

## Prerequisites

- Node.js / npm
- `trivy` を使う場合は Trivy インストール済み

## Package

```bash
cd vscode-extension/csap-sbom-security
npm install
npx @vscode/vsce package --allow-missing-repository --skip-license
```
