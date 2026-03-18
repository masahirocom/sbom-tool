class SbomDashboardViewProvider {
  constructor(vscode, getViewState) {
    this.vscode = vscode;
    this.getViewState = getViewState;
    this.currentView = null;
  }

  resolveWebviewView(webviewView) {
    this.currentView = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
    };

    webviewView.webview.onDidReceiveMessage(async (message) => {
      if (!message || message.type !== 'command' || typeof message.command !== 'string') {
        return;
      }
      await this.vscode.commands.executeCommand(message.command);
    });

    this.render();
  }

  render() {
    if (!this.currentView) {
      return;
    }

    const state = this.getViewState();
    this.currentView.webview.html = this.buildHtml(state);
  }

  buildHtml(state) {
    const escape = (value) =>
      String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    body {
      margin: 0;
      padding: 12px;
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background);
    }
    .card {
      border: 1px solid var(--vscode-panel-border);
      border-radius: 10px;
      padding: 10px;
      margin-bottom: 10px;
      background: var(--vscode-editor-background);
    }
    .title {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      opacity: 0.8;
      margin-bottom: 6px;
    }
    .value {
      font-size: 12px;
      line-height: 1.45;
      word-break: break-word;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }
    button {
      appearance: none;
      border: 1px solid var(--vscode-button-border, transparent);
      border-radius: 8px;
      padding: 9px 10px;
      font-size: 12px;
      font-weight: 700;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      cursor: pointer;
    }
    button.secondary {
      background: var(--vscode-inputOption-background);
      color: var(--vscode-inputOption-foreground);
      border-color: var(--vscode-inputOption-border, var(--vscode-panel-border));
    }
    button.wide {
      grid-column: span 2;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="title">${escape(state.labels.dashboardWorkspace)}</div>
    <div class="value">${escape(state.workspaceName)}</div>
  </div>

  <div class="card">
    <div class="title">${escape(state.labels.dashboardSettings)}</div>
    <div class="value">${escape(state.labels.dashboardSbomGenerator)}: ${escape(state.sbomGenerator)}</div>
    <div class="value">${escape(state.labels.dashboardScanner)}: ${escape(state.scanner)}</div>
    <div class="value">${escape(state.labels.dashboardUiLanguage)}: ${escape(state.uiLanguage)}</div>
    <div class="value">${escape(state.labels.dashboardOpenMode)}: ${escape(state.resultOpenMode)}</div>
  </div>

  <div class="grid">
    <button data-command="sbomTool.generateSbom">${escape(state.labels.dashboardGenerateSbom)}</button>
    <button data-command="sbomTool.scanVulnerabilities">${escape(state.labels.dashboardScan)}</button>
    <button data-command="sbomTool.generateAndScan" class="wide">${escape(state.labels.dashboardGenerateAndScan)}</button>
    <button data-command="sbomTool.checkCurrentProject" class="secondary wide">${escape(state.labels.dashboardCheckProject)}</button>
    <button data-command="sbomTool.installTools" class="secondary wide">${escape(state.labels.dashboardInstallTools)}</button>
    <button data-command="sbomTool.setSbomGenerator" class="secondary">${escape(state.labels.dashboardSetSbomGenerator)}</button>
    <button data-command="sbomTool.setScanner" class="secondary">${escape(state.labels.dashboardSetScanner)}</button>
    <button data-command="sbomTool.setUiLanguage" class="secondary">${escape(state.labels.dashboardSetUiLanguage)}</button>
    <button data-command="sbomTool.setResultOpenMode" class="secondary wide">${escape(state.labels.dashboardSetOpenMode)}</button>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    document.querySelectorAll('button[data-command]').forEach((button) => {
      button.addEventListener('click', () => {
        const command = button.getAttribute('data-command');
        if (!command || button.disabled) return;
        vscode.postMessage({ type: 'command', command });
      });
    });
  </script>
</body>
</html>`;
  }

  dispose() {}
}

module.exports = {
  SbomDashboardViewProvider,
};
