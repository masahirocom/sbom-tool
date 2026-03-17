const vscode = require('vscode');
const path = require('node:path');
const fs = require('node:fs');
const { SbomDashboardViewProvider } = require('./lib/dashboardView');
const { openResultFile } = require('./lib/reportViewer');
const { t, getUiLanguage } = require('./lib/i18n');
const {
  generateSBOM,
  exportSBOMAsCycloneDxJson,
  exportSBOMAsSpdx,
  checkProjectEnvironment,
  scanVulnerabilities,
  formatVulnerabilitySummary,
} = require('./lib/scanner');

let dashboardViewProvider;

function activate(context) {
  dashboardViewProvider = new SbomDashboardViewProvider(vscode, () => getDashboardState(vscode));

  const generateSbomCommand = vscode.commands.registerCommand('sbomTool.generateSbom', async () => {
    await runGenerateSbom(vscode);
  });

  const scanVulnerabilityCommand = vscode.commands.registerCommand('sbomTool.scanVulnerabilities', async () => {
    await runVulnerabilityScan(vscode);
  });

  const generateAndScanCommand = vscode.commands.registerCommand('sbomTool.generateAndScan', async () => {
    await runGenerateAndScan(vscode);
  });

  const checkCurrentProjectCommand = vscode.commands.registerCommand('sbomTool.checkCurrentProject', async () => {
    await runCheckCurrentProject(vscode);
  });

  const setScannerCommand = vscode.commands.registerCommand('sbomTool.setScanner', async () => {
    await setScanner(vscode);
  });

  const setUiLanguageCommand = vscode.commands.registerCommand('sbomTool.setUiLanguage', async () => {
    await setUiLanguage(vscode);
  });

  const setResultOpenModeCommand = vscode.commands.registerCommand('sbomTool.setResultOpenMode', async () => {
    await setResultOpenMode(vscode);
  });

  const dashboardProviderDisposable = vscode.window.registerWebviewViewProvider('sbomTool.dashboard', dashboardViewProvider);

  const configurationWatcher = vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration('sbomTool')) {
      dashboardViewProvider.render();
    }
  });

  context.subscriptions.push(
    generateSbomCommand,
    scanVulnerabilityCommand,
    generateAndScanCommand,
    checkCurrentProjectCommand,
    setScannerCommand,
    setUiLanguageCommand,
    setResultOpenModeCommand,
    dashboardProviderDisposable,
    configurationWatcher,
    dashboardViewProvider
  );
}

function deactivate() {}

async function pickTargetFolder(vscodeApi) {
  const folders = vscodeApi.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscodeApi.window.showErrorMessage(t(vscodeApi, 'Open a workspace folder before running this command.'));
    return undefined;
  }

  if (folders.length === 1) {
    return folders[0];
  }

  const picked = await vscodeApi.window.showQuickPick(
    folders.map((folder) => ({
      label: folder.name,
      description: folder.uri.fsPath,
      folder,
    })),
    { title: t(vscodeApi, 'Select target workspace for SBOM analysis') }
  );

  return picked ? picked.folder : undefined;
}

function ensureOutputDirectory(vscodeApi, workspacePath) {
  const config = vscodeApi.workspace.getConfiguration('sbomTool');
  const outputDirectory = config.get('outputDirectory', '.sbom-tool');
  const outputPath = path.resolve(workspacePath, outputDirectory);
  fs.mkdirSync(outputPath, { recursive: true });
  return outputPath;
}

function writeJsonFile(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

function writeTextFile(filePath, text) {
  fs.writeFileSync(filePath, text, 'utf-8');
}

function timestampSuffix() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function buildVulnerabilityHtmlReport(scanResult, workspacePath) {
  const title = `Vulnerability Report - ${path.basename(workspacePath)}`;

  function escapeHtml(value) {
    return String(value || '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function toSafeLink(url, label) {
    const value = String(url || '').trim();
    if (!/^https?:\/\//i.test(value)) {
      return '';
    }
    return `<a href="${escapeHtml(value)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label || value)}</a>`;
  }

  function buildReferenceCell(item) {
    const cveIds = new Set();
    const candidates = [item.cveId, item.title, item.description, item.reference, item.url];

    for (const candidate of candidates) {
      const text = String(candidate || '');
      const matches = text.match(/CVE-\d{4}-\d+/gi) || [];
      for (const match of matches) {
        cveIds.add(match.toUpperCase());
      }
    }

    if (cveIds.size === 0) {
      return '-';
    }

    return Array.from(cveIds)
      .sort()
      .map((cveId) => {
        const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
        return toSafeLink(nvdUrl, cveId);
      })
      .filter(Boolean)
      .join('<br/>');
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="light dark" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --bg: #ffffff;
      --fg: #1f2328;
      --muted: #57606a;
      --border: #d0d7de;
      --panel: #f6f8fa;
      --link: #0969da;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0d1117;
        --fg: #e6edf3;
        --muted: #9da7b3;
        --border: #30363d;
        --panel: #161b22;
        --link: #58a6ff;
      }
    }

    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 24px; color: var(--fg); background: var(--bg); }
    h1 { margin-bottom: 8px; }
    .meta { color: var(--muted); margin-bottom: 16px; }
    .pill { display:inline-block; margin-right:8px; margin-bottom:8px; padding: 4px 10px; border-radius: 999px; background: var(--panel); border:1px solid var(--border); font-size:12px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border: 1px solid var(--border); padding: 8px; font-size: 12px; text-align: left; vertical-align: top; }
    th { background: var(--panel); }
    a { color: var(--link); text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  <div class="meta">Generated at: ${escapeHtml(scanResult.timestamp)}</div>
  <div class="pill">Source: ${escapeHtml(scanResult.source)}</div>
  <div class="pill">Total: ${escapeHtml(scanResult.totalVulnerabilities)}</div>
  <div class="pill">Critical: ${escapeHtml(scanResult.critical)}</div>
  <div class="pill">High: ${escapeHtml(scanResult.high)}</div>
  <div class="pill">Moderate: ${escapeHtml(scanResult.moderate)}</div>
  <div class="pill">Low: ${escapeHtml(scanResult.low)}</div>
  <div class="pill">Fixable Packages: ${escapeHtml(scanResult.fixable)}</div>
  <p>${escapeHtml(scanResult.summary)}</p>
  <table>
    <thead>
      <tr>
        <th>Package</th>
        <th>Severity</th>
        <th>Title</th>
        <th>Current</th>
        <th>Fix</th>
        <th>CVE ID</th>
      </tr>
    </thead>
    <tbody>
      ${(scanResult.vulnerabilities || [])
        .slice(0, 200)
        .map(
          (item) => `
      <tr>
        <td>${escapeHtml(item.packageName || '')}</td>
        <td>${escapeHtml(item.severity || '')}</td>
        <td>${escapeHtml(item.title || '')}</td>
        <td>${escapeHtml(item.currentVersion || item.affectedRange || '')}</td>
        <td>${escapeHtml(item.proposedFix || '')}</td>
        <td>${buildReferenceCell(item)}</td>
      </tr>`
        )
        .join('')}
    </tbody>
  </table>
</body>
</html>`;
}

function buildProjectCheckMarkdown(environment, workspacePath) {
  let recommendation;
  if (!environment.packageJsonExists) {
    recommendation = '- package.json is missing. Vulnerability scan for npm dependencies may be skipped.';
  } else if (environment.trivyAvailable) {
    recommendation = '- Ready. Trivy is available, so vulnerability scanning can run immediately.';
  } else if (environment.npmAvailable && environment.packageLockExists) {
    recommendation = '- Ready. npm audit can run with the existing package-lock.json.';
  } else if (environment.npmAvailable && !environment.packageLockExists) {
    recommendation = '- Ready with auto-prepare. The tool will try to generate package-lock.json automatically before npm audit.';
  } else {
    recommendation = '- npm command not found. Install Node.js/npm or install Trivy for vulnerability scanning.';
  }

  return [
    `# Project Check`,
    '',
    `- Workspace: ${workspacePath}`,
    `- package.json: ${environment.packageJsonExists ? 'OK' : 'Missing'}`,
    `- package-lock.json: ${environment.packageLockExists ? 'OK' : 'Missing'}`,
    `- npm command: ${environment.npmAvailable ? 'Available' : 'Not found'}`,
    `- trivy command: ${environment.trivyAvailable ? 'Available' : 'Not found'}`,
    '',
    `## Recommendation`,
    recommendation,
  ].join('\n');
}

function getDashboardState(vscodeApi) {
  const folder = vscodeApi.workspace.workspaceFolders && vscodeApi.workspace.workspaceFolders[0];
  const config = vscodeApi.workspace.getConfiguration('sbomTool');
  const language = getUiLanguage(vscodeApi);

  return {
    workspaceName: folder ? folder.uri.fsPath : t(vscodeApi, 'dashboardNoWorkspace'),
    scanner: config.get('vulnerabilityScanner', 'auto'),
    uiLanguage: config.get('uiLanguage', 'auto'),
    resultOpenMode: config.get('resultOpenMode', 'vscode'),
    labels: {
      dashboardWorkspace: t(vscodeApi, 'dashboardWorkspace'),
      dashboardSettings: t(vscodeApi, 'dashboardSettings'),
      dashboardScanner: t(vscodeApi, 'dashboardScanner'),
      dashboardUiLanguage: t(vscodeApi, 'dashboardUiLanguage'),
      dashboardOpenMode: t(vscodeApi, 'dashboardOpenMode'),
      dashboardGenerateSbom: t(vscodeApi, 'dashboardGenerateSbom'),
      dashboardScan: t(vscodeApi, 'dashboardScan'),
      dashboardGenerateAndScan: t(vscodeApi, 'dashboardGenerateAndScan'),
      dashboardCheckProject: t(vscodeApi, 'dashboardCheckProject'),
      dashboardSetScanner: t(vscodeApi, 'dashboardSetScanner'),
      dashboardSetUiLanguage: t(vscodeApi, 'dashboardSetUiLanguage'),
      dashboardSetOpenMode: t(vscodeApi, 'dashboardSetOpenMode'),
    },
    language,
  };
}

async function runGenerateSbom(vscodeApi) {
  const targetFolder = await pickTargetFolder(vscodeApi);
  if (!targetFolder) return;

  await vscodeApi.window.withProgress(
    {
      location: vscodeApi.ProgressLocation.Notification,
      title: t(vscodeApi, 'Generating SBOM'),
      cancellable: false,
    },
    async () => {
      const config = vscodeApi.workspace.getConfiguration('sbomTool');
      const defaultFormat = config.get('defaultSbomFormat', 'cyclonedx-json');

      const sbom = generateSBOM(targetFolder.uri.fsPath);
      const outputPath = ensureOutputDirectory(vscodeApi, targetFolder.uri.fsPath);

      const suffix = timestampSuffix();
      const rawSbomPath = path.join(outputPath, `sbom-raw-${suffix}.json`);
      writeJsonFile(rawSbomPath, sbom);

      let exportPath;
      if (defaultFormat === 'spdx') {
        exportPath = path.join(outputPath, `sbom-spdx-${suffix}.spdx`);
        fs.writeFileSync(exportPath, exportSBOMAsSpdx(sbom), 'utf-8');
      } else {
        exportPath = path.join(outputPath, `sbom-cyclonedx-${suffix}.json`);
        fs.writeFileSync(exportPath, exportSBOMAsCycloneDxJson(sbom), 'utf-8');
      }

      await openResultFile(vscodeApi, exportPath, 'SBOM Result');
      vscodeApi.window.showInformationMessage(t(vscodeApi, 'SBOM generated: {0}', path.basename(exportPath)));
      dashboardViewProvider?.render();
    }
  );
}

async function runVulnerabilityScan(vscodeApi) {
  const targetFolder = await pickTargetFolder(vscodeApi);
  if (!targetFolder) return;

  await vscodeApi.window.withProgress(
    {
      location: vscodeApi.ProgressLocation.Notification,
      title: t(vscodeApi, 'Running vulnerability scan'),
      cancellable: false,
    },
    async () => {
      const config = vscodeApi.workspace.getConfiguration('sbomTool');
      const scannerPreference = config.get('vulnerabilityScanner', 'auto');

      const scanResult = await scanVulnerabilities(targetFolder.uri.fsPath, scannerPreference);
      const outputPath = ensureOutputDirectory(vscodeApi, targetFolder.uri.fsPath);
      const suffix = timestampSuffix();
      const reportPath = path.join(outputPath, `vulnerability-report-${suffix}.json`);
      writeJsonFile(reportPath, scanResult);
      const htmlReportPath = path.join(outputPath, `vulnerability-report-${suffix}.html`);
      writeTextFile(htmlReportPath, buildVulnerabilityHtmlReport(scanResult, targetFolder.uri.fsPath));

      const summary = formatVulnerabilitySummary(scanResult);
      await openResultFile(vscodeApi, htmlReportPath, 'Vulnerability Report');
      vscodeApi.window.showInformationMessage(summary);
      dashboardViewProvider?.render();
    }
  );
}

async function runGenerateAndScan(vscodeApi) {
  const targetFolder = await pickTargetFolder(vscodeApi);
  if (!targetFolder) return;

  await vscodeApi.window.withProgress(
    {
      location: vscodeApi.ProgressLocation.Notification,
      title: t(vscodeApi, 'Running SBOM generation + vulnerability scan'),
      cancellable: false,
    },
    async (progress) => {
      const workspacePath = targetFolder.uri.fsPath;
      const outputPath = ensureOutputDirectory(vscodeApi, workspacePath);
      const config = vscodeApi.workspace.getConfiguration('sbomTool');
      const scannerPreference = config.get('vulnerabilityScanner', 'auto');
      const defaultFormat = config.get('defaultSbomFormat', 'cyclonedx-json');

      progress.report({ message: t(vscodeApi, 'Generating SBOM...') });
      const sbom = generateSBOM(workspacePath);
      const suffix = timestampSuffix();
      const rawSbomPath = path.join(outputPath, `sbom-raw-${suffix}.json`);
      writeJsonFile(rawSbomPath, sbom);

      if (defaultFormat === 'spdx') {
        fs.writeFileSync(path.join(outputPath, `sbom-spdx-${suffix}.spdx`), exportSBOMAsSpdx(sbom), 'utf-8');
      } else {
        fs.writeFileSync(path.join(outputPath, `sbom-cyclonedx-${suffix}.json`), exportSBOMAsCycloneDxJson(sbom), 'utf-8');
      }

      progress.report({ message: t(vscodeApi, 'Running vulnerability scan...') });
      const scanResult = await scanVulnerabilities(workspacePath, scannerPreference);
      const reportPath = path.join(outputPath, `vulnerability-report-${suffix}.json`);
      writeJsonFile(reportPath, scanResult);
      const htmlReportPath = path.join(outputPath, `vulnerability-report-${suffix}.html`);
      writeTextFile(htmlReportPath, buildVulnerabilityHtmlReport(scanResult, workspacePath));

      const summary = formatVulnerabilitySummary(scanResult);
      await openResultFile(vscodeApi, htmlReportPath, 'SBOM + Vulnerability Report');
      vscodeApi.window.showInformationMessage(t(vscodeApi, 'Done: {0}', summary));
      dashboardViewProvider?.render();
    }
  );
}

async function runCheckCurrentProject(vscodeApi) {
  const targetFolder = await pickTargetFolder(vscodeApi);
  if (!targetFolder) return;

  const environment = await checkProjectEnvironment(targetFolder.uri.fsPath);
  const outputPath = ensureOutputDirectory(vscodeApi, targetFolder.uri.fsPath);
  const filePath = path.join(outputPath, `project-check-${timestampSuffix()}.md`);
  writeTextFile(filePath, buildProjectCheckMarkdown(environment, targetFolder.uri.fsPath));

  await openResultFile(vscodeApi, filePath, 'Project Check');
  vscodeApi.window.showInformationMessage(t(vscodeApi, 'checkProjectResultTitle'));
  dashboardViewProvider?.render();
}

async function setScanner(vscodeApi) {
  const config = vscodeApi.workspace.getConfiguration('sbomTool');
  const selected = await vscodeApi.window.showQuickPick(
    [
      { label: 'auto', description: 'Trivy first, fallback to npm audit' },
      { label: 'trivy', description: 'Use Trivy only' },
      { label: 'npm-audit', description: 'Use npm audit only' },
    ],
    { title: t(vscodeApi, 'scannerSelectionTitle') }
  );

  if (!selected) return;
  await config.update('vulnerabilityScanner', selected.label, vscodeApi.ConfigurationTarget.Workspace);
  vscodeApi.window.showInformationMessage(t(vscodeApi, 'scannerUpdated', selected.label));
  dashboardViewProvider?.render();
}

async function setUiLanguage(vscodeApi) {
  const config = vscodeApi.workspace.getConfiguration('sbomTool');
  const selected = await vscodeApi.window.showQuickPick(
    [
      { label: 'auto', description: 'Follow VS Code display language' },
      { label: 'en', description: 'English' },
      { label: 'ja', description: 'Japanese' },
    ],
    { title: t(vscodeApi, 'uiLanguageSelectionTitle') }
  );

  if (!selected) return;
  await config.update('uiLanguage', selected.label, vscodeApi.ConfigurationTarget.Workspace);
  vscodeApi.window.showInformationMessage(t(vscodeApi, 'uiLanguageUpdated', selected.label));
  dashboardViewProvider?.render();
}

async function setResultOpenMode(vscodeApi) {
  const config = vscodeApi.workspace.getConfiguration('sbomTool');
  const selected = await vscodeApi.window.showQuickPick(
    [
      { label: 'vscode', description: 'Open results in VS Code' },
      { label: 'external', description: 'Open results in external browser' },
    ],
    { title: t(vscodeApi, 'openModeSelectionTitle') }
  );

  if (!selected) return;
  await config.update('resultOpenMode', selected.label, vscodeApi.ConfigurationTarget.Workspace);
  vscodeApi.window.showInformationMessage(t(vscodeApi, 'openModeUpdated', selected.label));
  dashboardViewProvider?.render();
}

module.exports = {
  activate,
  deactivate,
};
