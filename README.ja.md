# SBOMツール

- English: [README.md](README.md)
- 日本語: [README.ja.md](README.ja.md)

SBOMツールは、現在開いているワークスペースに対してSBOM生成と脆弱性チェックを実行します。

## VSIXダウンロード

インストールには次のファイルを利用してください。

- [releases/sbom-tool-latest.vsix](releases/sbom-tool-latest.vsix)

バージョン固定で使いたい場合は [releases](releases) 配下のファイルを選択してください。

## ダッシュボード（アクティビティバー）

インストール後、アクティビティバーにSBOMツールのアイコンが表示されます。
ダッシュボードから次の操作が可能です。

- 現在開いているプロジェクトのチェック
- 脆弱性スキャナの切り替え（`auto` / `trivy` / `npm-audit`）
- UI言語の切り替え（`auto` / `en` / `ja`）
- 結果表示モードの切り替え（`vscode` / `external`）
- SBOM生成および脆弱性スキャンの実行

## コマンド

- `SBOM Tool: Generate SBOM`
- `SBOM Tool: Scan Vulnerabilities`
- `SBOM Tool: Generate SBOM + Scan Vulnerabilities`
- `SBOM Tool: Check Current Project`
- `SBOM Tool: Select Scanner`
- `SBOM Tool: Select UI Language`
- `SBOM Tool: Select Result Open Mode`

## 出力

デフォルトでは、ワークスペース内の`.sbom-tool/`に出力されます。

- `sbom-raw-*.json`: 内部解析用SBOMデータ
- `sbom-cyclonedx-*.json` または `sbom-spdx-*.spdx`: エクスポートされたSBOM
- `vulnerability-report-*.json`: 脆弱性スキャン結果

## 設定

- `sbomTool.outputDirectory`（初期値: `.sbom-tool`）
- `sbomTool.defaultSbomFormat`（初期値: `cyclonedx-json`）
  - `cyclonedx-json`
  - `spdx`
- `sbomTool.vulnerabilityScanner`（初期値: `auto`）
  - `auto`: Trivyを優先し、失敗時はnpm auditへフォールバック
  - `trivy`: Trivyのみ使用
  - `npm-audit`: npm auditのみ使用
- `sbomTool.uiLanguage`（初期値: `auto`）
  - `auto`: VS Codeの表示言語に追従
  - `en`: 英語
  - `ja`: 日本語
- `sbomTool.resultOpenMode`（初期値: `vscode`）
  - `vscode`: 結果をVS Code内で表示
  - `external`: 結果を外部ブラウザーで表示

## 前提条件

- Node.js / npm
- Trivy（`trivy`モードを使う場合）

## 言語サポート

- 既定言語: 英語
- 日本語対応: あり（VS Codeの表示言語が`ja`の場合）

## パッケージ作成

```bash
cd vscode-extension/csap-sbom-security
npm install
npm run package:release
```

## ライセンス

Apache License 2.0
