function getUiLanguage(vscode) {
  const configValue = vscode.workspace.getConfiguration('sbomTool').get('uiLanguage', 'auto');
  if (configValue === 'en' || configValue === 'ja') {
    return configValue;
  }

  const vscodeLanguage = String(vscode.env.language || 'en').toLowerCase();
  return vscodeLanguage.startsWith('ja') ? 'ja' : 'en';
}

const dictionary = {
  en: {
    openWorkspaceFirst: 'Open a workspace folder before running this command.',
    selectWorkspace: 'Select target workspace for SBOM analysis',
    progressGenerateSbom: 'Generating SBOM',
    progressScanVulnerability: 'Running vulnerability scan',
    progressGenerateAndScan: 'Running SBOM generation + vulnerability scan',
    progressGenerateSbomStep: 'Generating SBOM...',
    progressScanStep: 'Running vulnerability scan...',
    sbomGenerated: 'SBOM generated: {0}',
    openOutputFolder: 'Open output folder',
    done: 'Done: {0}',
    openReport: 'Open report',
    checkProjectResultTitle: 'Project check completed',
    scannerSelectionTitle: 'Select vulnerability scanner',
    sbomGeneratorSelectionTitle: 'Select SBOM generator',
    uiLanguageSelectionTitle: 'Select UI language',
    openModeSelectionTitle: 'Select result open mode',
    installToolsStarted: 'Started Homebrew installation for Syft and Trivy in the integrated terminal.',
    installToolsRequiresBrew: 'Homebrew is required to install Syft and Trivy automatically on macOS.',
    installToolsUnsupportedPlatform: 'Automatic Syft and Trivy installation is currently supported only on macOS with Homebrew.',
    installToolsRecommendation: 'Syft and Trivy are not installed, so SBOM generation fell back to limited manifest mode. Install them now?',
    installTrivyRecommendation: 'Trivy is not installed. Install Syft and Trivy now?',
    installToolsAction: 'Install now',
    openHomebrewSite: 'Open Homebrew site',
    scannerUpdated: 'Scanner updated: {0}',
    sbomGeneratorUpdated: 'SBOM generator updated: {0}',
    uiLanguageUpdated: 'UI language updated: {0}',
    openModeUpdated: 'Result open mode updated: {0}',
    dashboardTitle: 'SBOM Vulnerability Scanner Dashboard',
    dashboardWorkspace: 'Workspace',
    dashboardNoWorkspace: 'No workspace opened',
    dashboardSettings: 'Settings',
    dashboardSbomGenerator: 'SBOM Generator',
    dashboardScanner: 'Scanner',
    dashboardUiLanguage: 'UI Language',
    dashboardOpenMode: 'Result Open',
    dashboardActions: 'Actions',
    dashboardGenerateSbom: 'Generate SBOM',
    dashboardScan: 'Scan Vulnerabilities',
    dashboardGenerateAndScan: 'Generate + Scan',
    dashboardCheckProject: 'Check Current Project',
    dashboardInstallTools: 'Install Syft / Trivy',
    dashboardSetSbomGenerator: 'Change SBOM Generator',
    dashboardSetScanner: 'Change Scanner',
    dashboardSetUiLanguage: 'Change Language',
    dashboardSetOpenMode: 'Change Open Mode',
  },
  ja: {
    openWorkspaceFirst: 'このコマンドを実行する前にワークスペースフォルダを開いてください。',
    selectWorkspace: 'SBOM解析の対象ワークスペースを選択',
    progressGenerateSbom: 'SBOMを生成中',
    progressScanVulnerability: '脆弱性スキャン実行中',
    progressGenerateAndScan: 'SBOM生成 + 脆弱性スキャンを実行中',
    progressGenerateSbomStep: 'SBOMを生成中...',
    progressScanStep: '脆弱性スキャンを実行中...',
    sbomGenerated: 'SBOMを生成しました: {0}',
    openOutputFolder: '出力フォルダを開く',
    done: '完了: {0}',
    openReport: 'レポートを開く',
    checkProjectResultTitle: 'プロジェクトチェックが完了しました',
    scannerSelectionTitle: '脆弱性スキャナを選択',
    sbomGeneratorSelectionTitle: 'SBOM生成器を選択',
    uiLanguageSelectionTitle: 'UI言語を選択',
    openModeSelectionTitle: '結果表示モードを選択',
    installToolsStarted: '統合ターミナルで Syft と Trivy の Homebrew インストールを開始しました。',
    installToolsRequiresBrew: 'macOS で Syft と Trivy を自動インストールするには Homebrew が必要です。',
    installToolsUnsupportedPlatform: 'Syft と Trivy の自動インストールは現在 macOS + Homebrew のみ対応です。',
    installToolsRecommendation: 'Syft と Trivy が未導入のため、SBOM生成は限定的な manifest モードにフォールバックしました。今インストールしますか。',
    installTrivyRecommendation: 'Trivy が未導入です。Syft と Trivy を今インストールしますか。',
    installToolsAction: '今すぐインストール',
    openHomebrewSite: 'Homebrew サイトを開く',
    scannerUpdated: 'スキャナを更新しました: {0}',
    sbomGeneratorUpdated: 'SBOM生成器を更新しました: {0}',
    uiLanguageUpdated: 'UI言語を更新しました: {0}',
    openModeUpdated: '結果表示モードを更新しました: {0}',
    dashboardTitle: 'SBOM Vulnerability Scanner ダッシュボード',
    dashboardWorkspace: 'ワークスペース',
    dashboardNoWorkspace: 'ワークスペースが開かれていません',
    dashboardSettings: '設定',
    dashboardSbomGenerator: 'SBOM生成器',
    dashboardScanner: 'スキャナ',
    dashboardUiLanguage: 'UI言語',
    dashboardOpenMode: '結果表示',
    dashboardActions: 'アクション',
    dashboardGenerateSbom: 'SBOM生成',
    dashboardScan: '脆弱性スキャン',
    dashboardGenerateAndScan: '生成 + スキャン',
    dashboardCheckProject: '現在のプロジェクトをチェック',
    dashboardInstallTools: 'Syft / Trivy をインストール',
    dashboardSetSbomGenerator: '生成器変更',
    dashboardSetScanner: 'スキャナ変更',
    dashboardSetUiLanguage: '言語変更',
    dashboardSetOpenMode: '表示モード変更',
  },
};

function format(template, args) {
  return String(template).replace(/\{(\d+)\}/g, (_, index) => String(args[Number(index)] ?? ''));
}

function t(vscode, key, ...args) {
  const language = getUiLanguage(vscode);
  const table = dictionary[language] || dictionary.en;
  const template = table[key] || dictionary.en[key] || key;
  return format(template, args);
}

module.exports = {
  t,
  getUiLanguage,
};
