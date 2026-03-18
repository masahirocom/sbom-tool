# SBOM Vulnerability Scanner

**GitHubリポジトリ**: [masahirocom/sbom-vulnerability-scanner](https://github.com/masahirocom/sbom-vulnerability-scanner)

- English: [README.md](README.md)
- 日本語: [README.ja.md](README.ja.md)

SBOM Vulnerability Scanner は、現在開いているワークスペースに対してSBOM生成と脆弱性チェックを実行します。

## VSIXダウンロード

インストールには次のファイルを利用してください。

- [releases/sbom-vulnerability-scanner-latest.vsix](releases/sbom-vulnerability-scanner-latest.vsix)

バージョン固定で使いたい場合は [releases](releases) 配下のファイルを選択してください。
例: `releases/sbom-vulnerability-scanner-<version>.vsix`

## Marketplaceからインストール（推奨）

VS Code Marketplaceに公開後は、拡張ビューからSBOM Vulnerability Scanner をインストールできます。
Marketplace経由でインストールした場合は自動アップデートに対応します。

## ダッシュボード（アクティビティバー）

インストール後、アクティビティバーに SBOM Vulnerability Scanner のアイコンが表示されます。
ダッシュボードから次の操作が可能です。

- 現在開いているプロジェクトのチェック
- SBOM生成器の切り替え（`auto` / `syft` / `trivy` / `manifest`）
- 脆弱性スキャナの切り替え（`auto` / `trivy` / `npm-audit`）
- UI言語の切り替え（`auto` / `en` / `ja`）
- 結果表示モードの切り替え（`vscode` / `external`）
- SBOM生成および脆弱性スキャンの実行

## コマンド

- `SBOM Vulnerability Scanner: Generate SBOM`
- `SBOM Vulnerability Scanner: Scan Vulnerabilities`
- `SBOM Vulnerability Scanner: Generate SBOM + Scan Vulnerabilities`
- `SBOM Vulnerability Scanner: Check Current Project`
- `SBOM Vulnerability Scanner: Select Scanner`
- `SBOM Vulnerability Scanner: Select SBOM Generator`
- `SBOM Vulnerability Scanner: Select UI Language`
- `SBOM Vulnerability Scanner: Select Result Open Mode`
- `SBOM Vulnerability Scanner: Syft と Trivy をセットアップ`

このセットアップコマンドは、ユーザーが明示的に実行する前提です。
- **macOS/Linux (Homebrew あり)**: ユーザーが選択したときだけ統合ターミナルで `brew install syft trivy` を実行
- **Windows (WinGet あり)**: ユーザーが選択したときだけ統合ターミナルで `winget install Anchore.syft AquaSecurity.Trivy` を実行
- **Windows (Scoop あり)**: ユーザーが選択したときだけ統合ターミナルで `scoop install syft trivy` を実行  
- **全プラットフォーム**: GitHub Releases からバイナリをダウンロードするか、公式ガイドを確認可能

## 出力

デフォルトでは、ワークスペース内の`.sbom-tool/`に出力されます。

- `sbom-raw-*.json`: 内部解析用SBOMデータ
- `sbom-cyclonedx-*.json` または `sbom-spdx-*.*`: エクスポートされたSBOM
- `sbom-report-*.html`: 人が読みやすいSBOMレポート
- `vulnerability-report-*.json`: 脆弱性スキャン結果

## 設定

- `sbomTool.outputDirectory`（初期値: `.sbom-tool`）
- `sbomTool.defaultSbomFormat`（初期値: `cyclonedx-json`）
  - `cyclonedx-json`
  - `spdx`
- `sbomTool.sbomGenerator`（初期値: `auto`）
  - `auto`: Syft を優先し、次に Trivy、最後に組み込みマニフェスト解析へフォールバック
  - `syft`: Syft のみ使用
  - `trivy`: Trivy のみ使用
  - `manifest`: 組み込みマニフェスト解析のみ使用
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

- 幅広い言語とパッケージマネージャに対応するには Syft
- Trivy ベースのSBOM生成や脆弱性スキャンを使う場合は Trivy
- 組み込みマニフェスト解析や npm audit を使う場合は Node.js / npm

ダッシュボードまたはコマンドパレットのセットアップコマンドから、導入方法を明示的に選択してください。

## 言語サポート

- 既定言語: 英語
- 日本語対応: あり（VS Codeの表示言語が`ja`の場合）

## パッケージ作成

```bash
cd vscode-extension/csap-sbom-security
npm install
npm run release:patch
```

## 公開（Marketplace）

```bash
cd vscode-extension/csap-sbom-security
npm install
npm run publish:patch
```

Publisher設定やPATの詳細手順は [PUBLISHING.md](PUBLISHING.md) を参照してください。

## ライセンス

Apache License 2.0
