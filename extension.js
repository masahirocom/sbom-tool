const vscode = require('vscode');
const path = require('node:path');
const fs = require('node:fs');
const { execSync } = require('node:child_process');
const { SbomDashboardViewProvider } = require('./lib/dashboardView');
const { openResultFile } = require('./lib/reportViewer');
const { t, getUiLanguage } = require('./lib/i18n');
const {
  generateSBOM,
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

  const setSbomGeneratorCommand = vscode.commands.registerCommand('sbomTool.setSbomGenerator', async () => {
    await setSbomGenerator(vscode);
  });

  const setUiLanguageCommand = vscode.commands.registerCommand('sbomTool.setUiLanguage', async () => {
    await setUiLanguage(vscode);
  });

  const setResultOpenModeCommand = vscode.commands.registerCommand('sbomTool.setResultOpenMode', async () => {
    await setResultOpenMode(vscode);
  });

  const installToolsCommand = vscode.commands.registerCommand('sbomTool.installTools', async () => {
    await installSbomTools(vscode);
  });

  const openLatestSbomReportCommand = vscode.commands.registerCommand('sbomTool.openLatestSbomReport', async () => {
    await openLatestResult(vscode, {
      title: 'SBOM Report',
      missingLabel: t(vscode, 'resultLabelSbomReport'),
      rules: [{ prefix: 'sbom-report-', extension: '.html' }],
    });
  });

  const openLatestVulnerabilityReportCommand = vscode.commands.registerCommand('sbomTool.openLatestVulnerabilityReport', async () => {
    await openLatestResult(vscode, {
      title: 'Vulnerability Report',
      missingLabel: t(vscode, 'resultLabelVulnerabilityReport'),
      rules: [{ prefix: 'vulnerability-report-', extension: '.html' }],
    });
  });

  const openLatestSbomJsonCommand = vscode.commands.registerCommand('sbomTool.openLatestSbomJson', async () => {
    await openLatestResult(vscode, {
      title: 'SBOM JSON',
      missingLabel: t(vscode, 'resultLabelSbomJson'),
      rules: [
        { prefix: 'sbom-raw-', extension: '.json' },
        { prefix: 'sbom-cyclonedx-', extension: '.json' },
      ],
    });
  });

  const openLatestVulnerabilityJsonCommand = vscode.commands.registerCommand('sbomTool.openLatestVulnerabilityJson', async () => {
    await openLatestResult(vscode, {
      title: 'Vulnerability JSON',
      missingLabel: t(vscode, 'resultLabelVulnerabilityJson'),
      rules: [{ prefix: 'vulnerability-report-', extension: '.json' }],
    });
  });

  const openOutputDirectoryCommand = vscode.commands.registerCommand('sbomTool.openOutputDirectory', async () => {
    await openOutputDirectory(vscode);
  });

  const cleanOldResultsCommand = vscode.commands.registerCommand('sbomTool.cleanOldResults', async () => {
    await cleanOldResults(vscode);
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
    setSbomGeneratorCommand,
    setUiLanguageCommand,
    setResultOpenModeCommand,
    installToolsCommand,
    openLatestSbomReportCommand,
    openLatestVulnerabilityReportCommand,
    openLatestSbomJsonCommand,
    openLatestVulnerabilityJsonCommand,
    openOutputDirectoryCommand,
    cleanOldResultsCommand,
    dashboardProviderDisposable,
    configurationWatcher,
    dashboardViewProvider
  );
}

function deactivate() {
  return undefined;
}

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

function listResultFiles(outputPath) {
  if (!fs.existsSync(outputPath)) {
    return [];
  }

  return fs
    .readdirSync(outputPath, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => {
      const fullPath = path.join(outputPath, entry.name);
      const stat = fs.statSync(fullPath);
      return {
        name: entry.name,
        fullPath,
        mtimeMs: stat.mtimeMs,
      };
    })
    .sort((left, right) => right.mtimeMs - left.mtimeMs);
}

function findLatestByRules(resultFiles, rules) {
  for (const rule of rules) {
    const matched = resultFiles.find((file) =>
      file.name.startsWith(rule.prefix) && file.name.endsWith(rule.extension)
    );
    if (matched) {
      return matched;
    }
  }

  return undefined;
}

async function openLatestResult(vscodeApi, options) {
  const targetFolder = await pickTargetFolder(vscodeApi);
  if (!targetFolder) return;

  const outputPath = ensureOutputDirectory(vscodeApi, targetFolder.uri.fsPath);
  const resultFiles = listResultFiles(outputPath);
  const latest = findLatestByRules(resultFiles, options.rules || []);

  if (!latest) {
    vscodeApi.window.showWarningMessage(t(vscodeApi, 'noGeneratedFileFound', options.missingLabel || 'result'));
    return;
  }

  await openResultFile(vscodeApi, latest.fullPath, options.title || latest.name);
}

async function openOutputDirectory(vscodeApi) {
  const targetFolder = await pickTargetFolder(vscodeApi);
  if (!targetFolder) return;

  const outputPath = ensureOutputDirectory(vscodeApi, targetFolder.uri.fsPath);
  await vscodeApi.commands.executeCommand('revealFileInOS', vscodeApi.Uri.file(outputPath));
}

async function cleanOldResults(vscodeApi) {
  const targetFolder = await pickTargetFolder(vscodeApi);
  if (!targetFolder) return;

  const outputPath = ensureOutputDirectory(vscodeApi, targetFolder.uri.fsPath);
  const resultFiles = listResultFiles(outputPath).filter((file) =>
    /^(sbom-raw-|sbom-cyclonedx-|sbom-spdx-|sbom-report-|vulnerability-report-|project-check-)/.test(file.name)
  );

  if (resultFiles.length === 0) {
    vscodeApi.window.showInformationMessage(t(vscodeApi, 'noOldResultsToDelete'));
    return;
  }

  const selected = await vscodeApi.window.showQuickPick(
    [
      {
        label: 'keep-latest',
        description: t(vscodeApi, 'cleanKeepLatestDescription'),
      },
      {
        label: 'delete-all',
        description: t(vscodeApi, 'cleanDeleteAllDescription'),
      },
    ],
    { title: t(vscodeApi, 'cleanOldResultsTitle') }
  );

  if (!selected) return;

  let deleteTargets = [];
  if (selected.label === 'delete-all') {
    deleteTargets = resultFiles;
  } else {
    function getGroupKey(fileName) {
      if (fileName.startsWith('sbom-raw-') && fileName.endsWith('.json')) return 'sbom-raw-json';
      if (fileName.startsWith('sbom-cyclonedx-') && fileName.endsWith('.json')) return 'sbom-cyclonedx-json';
      if (fileName.startsWith('sbom-spdx-')) return 'sbom-spdx';
      if (fileName.startsWith('sbom-report-') && fileName.endsWith('.html')) return 'sbom-report-html';
      if (fileName.startsWith('vulnerability-report-') && fileName.endsWith('.json')) return 'vulnerability-report-json';
      if (fileName.startsWith('vulnerability-report-') && fileName.endsWith('.html')) return 'vulnerability-report-html';
      if (fileName.startsWith('project-check-') && fileName.endsWith('.md')) return 'project-check-md';
      return 'other';
    }

    const latestByGroup = new Map();
    for (const file of resultFiles) {
      const key = getGroupKey(file.name);
      if (!latestByGroup.has(key)) {
        latestByGroup.set(key, file);
      }
    }

    const keepSet = new Set(Array.from(latestByGroup.values()).map((file) => file.fullPath));
    deleteTargets = resultFiles.filter((file) => !keepSet.has(file.fullPath));
  }

  for (const file of deleteTargets) {
    try {
      fs.unlinkSync(file.fullPath);
    } catch {
    }
  }

  if (deleteTargets.length === 0) {
    vscodeApi.window.showInformationMessage(t(vscodeApi, 'noOldResultsToDelete'));
  } else {
    vscodeApi.window.showInformationMessage(t(vscodeApi, 'oldResultsDeleted', deleteTargets.length));
  }
}

function writeJsonFile(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

function writeTextFile(filePath, text) {
  fs.writeFileSync(filePath, text, 'utf-8');
}

function isCommandAvailable(command) {
  try {
    const checkCommand = process.platform === 'win32' ? `where ${command}` : `which ${command}`;
    execSync(checkCommand, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function timestampSuffix() {
  return new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-');
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function describeComponentScope(component) {
  if (component.scope) {
    return component.scope;
  }

  if (component.isDirect) {
    return 'required';
  }

  if (component.isTransitive) {
    return 'indirect';
  }

  return 'unknown';
}

function buildSbomHtmlReport(sbomResult, workspacePath) {
  const normalized = sbomResult.normalized || { components: [], dependencies: [], metadata: {} };
  const components = Array.isArray(normalized.components) ? normalized.components : [];
  const metadata = normalized.metadata || {};
  const title = `SBOM Report - ${path.basename(workspacePath)}`;

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
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0d1117;
        --fg: #c9d1d9;
        --muted: #8b949e;
        --border: #30363d;
        --panel: #161b22;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: var(--fg);
      background: var(--bg);
    }
    h1, h2 { margin: 0 0 8px 0; }
    h1 { font-size: 28px; }
    h2 { font-size: 20px; }
    p { margin: 0; }
    .meta { color: var(--muted); margin-bottom: 18px; }
    .summary {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 16px;
      line-height: 1.6;
    }
    .section { margin-top: 20px; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 8px;
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }
    th {
      background: var(--panel);
      font-weight: 600;
    }
    code {
      font-family: SFMono-Regular, Consolas, monospace;
      font-size: 12px;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  <p class="meta">Generated at ${escapeHtml(metadata.timestamp)} using ${escapeHtml(metadata.sbomGenerator || sbomResult.generator || 'unknown')} (${escapeHtml(metadata.generatorVersion || 'unknown version')})</p>
  <div class="summary">
    <div>Project: ${escapeHtml(metadata.projectName || path.basename(workspacePath))}</div>
    <div>Version: ${escapeHtml(metadata.projectVersion || 'unknown')}</div>
    <div>Components: ${escapeHtml(components.length)}</div>
    <div>Format: ${escapeHtml(sbomResult.exportFormat || metadata.sourceFormat || 'unknown')}</div>
    <div>Generator: ${escapeHtml(metadata.sbomGenerator || sbomResult.generator || 'unknown')}</div>
    ${metadata.warning ? `<div>Note: ${escapeHtml(metadata.warning)}</div>` : ''}
  </div>

  <div class="section">
    <h2>Component List</h2>
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Version</th>
          <th>Type</th>
          <th>Scope</th>
          <th>Licenses</th>
          <th>PURL / Ref</th>
        </tr>
      </thead>
      <tbody>
        ${components.length === 0
          ? `<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:16px;">No components detected. If you expected results, check that Syft or Trivy scanned the correct directory and that lock files are present.</td></tr>`
          : components.slice(0, 500).map((component) => `
        <tr>
          <td>${escapeHtml(component.name || '')}</td>
          <td>${escapeHtml(component.version || '')}</td>
          <td>${escapeHtml(component.type || '')}</td>
          <td>${escapeHtml(describeComponentScope(component))}</td>
          <td>${escapeHtml(Array.isArray(component.licenses) && component.licenses.length > 0 ? component.licenses.join(', ') : '-')}</td>
          <td><code>${escapeHtml(component.purl || component.id || '')}</code></td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>
</body>
</html>`;
}

async function ensureSbomToolsInstalled(vscodeApi, workspacePath) {
  const environment = await checkProjectEnvironment(workspacePath);
  if (environment.syftAvailable || environment.trivyAvailable) {
    return true;
  }

  const selected = await vscodeApi.window.showWarningMessage(
    t(vscodeApi, 'sbomToolsMissingMessage'),
    t(vscodeApi, 'sbomToolsMissingSetupAction')
  );

  if (selected === t(vscodeApi, 'sbomToolsMissingSetupAction')) {
    await vscodeApi.commands.executeCommand('sbomTool.installTools');
  }

  return false;
}

function buildVulnerabilityHtmlReport(scanResult, workspacePath) {
  const title = `Vulnerability Report - ${path.basename(workspacePath)}`;

  function escapeHtml(value) {
    return String(value ?? '')
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
    const advisoryIds = new Set();
    const candidates = [item.cveId, item.title, item.description, item.reference, item.url];

    for (const candidate of candidates) {
      const text = String(candidate || '');
      const matches = text.match(/CVE-\d{4}-\d+/gi) || [];
      for (const match of matches) {
        cveIds.add(match.toUpperCase());
      }

      const ghsaMatches = text.match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/gi) || [];
      for (const match of ghsaMatches) {
        advisoryIds.add(match.toUpperCase());
      }
    }

    const links = [];

    if (cveIds.size > 0) {
      links.push(
        ...Array.from(cveIds)
          .sort()
          .map((cveId) => {
            const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
            return toSafeLink(nvdUrl, cveId);
          })
          .filter(Boolean)
      );
    }

    if (advisoryIds.size > 0) {
      links.push(
        ...Array.from(advisoryIds)
          .sort()
          .map((advisoryId) => {
            const ghsaUrl = `https://github.com/advisories/${encodeURIComponent(advisoryId)}`;
            return toSafeLink(ghsaUrl, advisoryId);
          })
          .filter(Boolean)
      );
    }

    const fallbackReference = toSafeLink(item.url || item.reference, 'Advisory');
    if (links.length === 0 && fallbackReference) {
      links.push(fallbackReference);
    }

    return links.length > 0 ? links.join('<br/>') : '-';
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
        <th>CVE / Advisory</th>
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
  if (environment.syftAvailable) {
    recommendation = '- Ready. Syft is available, so broad SBOM generation can run across multiple ecosystems.';
  } else if (environment.trivyAvailable) {
    recommendation = '- Ready. Trivy is available, so broad SBOM generation and vulnerability scanning can run immediately.';
  } else if (!environment.packageJsonExists) {
    recommendation = '- No general SBOM CLI found. Install Syft or Trivy for broad language support.';
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
    `- syft command: ${environment.syftAvailable ? 'Available' : 'Not found'}`,
    `- npm command: ${environment.npmAvailable ? 'Available' : 'Not found'}`,
    `- trivy command: ${environment.trivyAvailable ? 'Available' : 'Not found'}`,
    '',
    `## Recommendation`,
    recommendation,
  ].join('\n');
}

async function installSbomTools(vscodeApi) {
  const setupItems = [];
  const brewAvailable = isCommandAvailable('brew');
  const wingetAvailable = isCommandAvailable('winget');
  const scoopAvailable = isCommandAvailable('scoop');

  // macOS with Homebrew
  if (process.platform === 'darwin' && brewAvailable) {
    setupItems.push({
      label: t(vscodeApi, 'installWithHomebrew'),
      description: t(vscodeApi, 'installWithHomebrewDescription'),
      action: 'brew',
    });
  }

  // macOS without Homebrew - offer Homebrew setup
  if (process.platform === 'darwin' && !brewAvailable) {
    setupItems.push({
      label: t(vscodeApi, 'openHomebrewSite'),
      description: t(vscodeApi, 'openHomebrewSiteDescription'),
      action: 'homebrew',
    });
  }

  // Windows with WinGet
  if (process.platform === 'win32' && wingetAvailable) {
    setupItems.push({
      label: t(vscodeApi, 'installWithWinget'),
      description: t(vscodeApi, 'installWithWingetDescription'),
      action: 'winget',
    });
  }

  // Windows with Scoop
  if (process.platform === 'win32' && scoopAvailable) {
    setupItems.push({
      label: t(vscodeApi, 'installWithScoop'),
      description: t(vscodeApi, 'installWithScoopDescription'),
      action: 'scoop',
    });
  }

  // Linux/Unix with install script
  if ((process.platform === 'linux' || process.platform === 'darwin') && isCommandAvailable('curl')) {
    setupItems.push({
      label: t(vscodeApi, 'installWithScript'),
      description: t(vscodeApi, 'installWithScriptDescription'),
      action: 'script',
    });
  }

  // GitHub Releases/Download (all platforms)
  setupItems.push(
    {
      label: t(vscodeApi, 'downloadFromGithubReleases'),
      description: t(vscodeApi, 'downloadFromGithubReleasesDescription'),
      action: 'releases',
    },
    {
      label: t(vscodeApi, 'openSyftInstallGuide'),
      description: 'https://oss.anchore.com/docs/installation/syft/',
      action: 'syft-docs',
    },
    {
      label: t(vscodeApi, 'openTrivyInstallGuide'),
      description: 'https://trivy.dev/docs/latest/getting-started/installation/',
      action: 'trivy-docs',
    }
  );

  const selected = await vscodeApi.window.showQuickPick(setupItems, {
    title: t(vscodeApi, 'toolSetupTitle'),
  });

  if (!selected) {
    return;
  }

  if (selected.action === 'brew') {
    const terminal = vscodeApi.window.createTerminal('SBOM Vulnerability Scanner Setup');
    terminal.show();
    terminal.sendText('brew install syft trivy', true);
    vscodeApi.window.showInformationMessage(t(vscodeApi, 'installToolsStarted'));
    return;
  }

  if (selected.action === 'homebrew') {
    await vscodeApi.env.openExternal(vscodeApi.Uri.parse('https://brew.sh/'));
    return;
  }

  if (selected.action === 'winget') {
    const terminal = vscodeApi.window.createTerminal('SBOM Vulnerability Scanner Setup');
    terminal.show();
    terminal.sendText('winget install Anchore.syft AquaSecurity.Trivy', true);
    vscodeApi.window.showInformationMessage('Started WinGet installation for Syft and Trivy in the integrated terminal.');
    return;
  }

  if (selected.action === 'scoop') {
    const terminal = vscodeApi.window.createTerminal('SBOM Vulnerability Scanner Setup');
    terminal.show();
    terminal.sendText('scoop install syft trivy', true);
    vscodeApi.window.showInformationMessage('Started Scoop installation for Syft and Trivy in the integrated terminal.');
    return;
  }

  if (selected.action === 'script') {
    const terminal = vscodeApi.window.createTerminal('SBOM Vulnerability Scanner Setup');
    terminal.show();
    terminal.sendText('curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin', true);
    terminal.sendText('curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin', true);
    vscodeApi.window.showInformationMessage('Started installation of Syft and Trivy using official install scripts in the integrated terminal.');
    return;
  }

  if (selected.action === 'releases') {
    await vscodeApi.env.openExternal(vscodeApi.Uri.parse('https://github.com/anchore/syft/releases'));
    return;
  }

  if (selected.action === 'syft-docs') {
    await vscodeApi.env.openExternal(vscodeApi.Uri.parse('https://oss.anchore.com/docs/installation/syft/'));
    return;
  }

  await vscodeApi.env.openExternal(vscodeApi.Uri.parse('https://trivy.dev/docs/latest/getting-started/installation/'));
}

function getDashboardState(vscodeApi) {
  const folder = vscodeApi.workspace.workspaceFolders && vscodeApi.workspace.workspaceFolders[0];
  const config = vscodeApi.workspace.getConfiguration('sbomTool');
  const language = getUiLanguage(vscodeApi);

  return {
    workspaceName: folder ? folder.uri.fsPath : t(vscodeApi, 'dashboardNoWorkspace'),
    scanner: config.get('vulnerabilityScanner', 'auto'),
    sbomGenerator: config.get('sbomGenerator', 'auto'),
    uiLanguage: config.get('uiLanguage', 'auto'),
    resultOpenMode: config.get('resultOpenMode', 'vscode'),
    labels: {
      dashboardWorkspace: t(vscodeApi, 'dashboardWorkspace'),
      dashboardSettings: t(vscodeApi, 'dashboardSettings'),
      dashboardScanner: t(vscodeApi, 'dashboardScanner'),
      dashboardSbomGenerator: t(vscodeApi, 'dashboardSbomGenerator'),
      dashboardUiLanguage: t(vscodeApi, 'dashboardUiLanguage'),
      dashboardOpenMode: t(vscodeApi, 'dashboardOpenMode'),
      dashboardGenerateSbom: t(vscodeApi, 'dashboardGenerateSbom'),
      dashboardScan: t(vscodeApi, 'dashboardScan'),
      dashboardGenerateAndScan: t(vscodeApi, 'dashboardGenerateAndScan'),
      dashboardCheckProject: t(vscodeApi, 'dashboardCheckProject'),
      dashboardInstallTools: t(vscodeApi, 'dashboardInstallTools'),
      dashboardSetScanner: t(vscodeApi, 'dashboardSetScanner'),
      dashboardSetSbomGenerator: t(vscodeApi, 'dashboardSetSbomGenerator'),
      dashboardSetUiLanguage: t(vscodeApi, 'dashboardSetUiLanguage'),
      dashboardSetOpenMode: t(vscodeApi, 'dashboardSetOpenMode'),
      dashboardOpenLatestSbomReport: t(vscodeApi, 'dashboardOpenLatestSbomReport'),
      dashboardOpenLatestVulnerabilityReport: t(vscodeApi, 'dashboardOpenLatestVulnerabilityReport'),
      dashboardOpenLatestSbomJson: t(vscodeApi, 'dashboardOpenLatestSbomJson'),
      dashboardOpenLatestVulnerabilityJson: t(vscodeApi, 'dashboardOpenLatestVulnerabilityJson'),
      dashboardOpenOutputDirectory: t(vscodeApi, 'dashboardOpenOutputDirectory'),
      dashboardCleanOldResults: t(vscodeApi, 'dashboardCleanOldResults'),
    },
    language,
  };
}

async function runGenerateSbom(vscodeApi) {
  const targetFolder = await pickTargetFolder(vscodeApi);
  if (!targetFolder) return;
  if (!(await ensureSbomToolsInstalled(vscodeApi, targetFolder.uri.fsPath))) return;

  await vscodeApi.window.withProgress(
    {
      location: vscodeApi.ProgressLocation.Notification,
      title: t(vscodeApi, 'Generating SBOM'),
      cancellable: false,
    },
    async () => {
      const config = vscodeApi.workspace.getConfiguration('sbomTool');
      const defaultFormat = config.get('defaultSbomFormat', 'cyclonedx-json');
      const sbomGenerator = config.get('sbomGenerator', 'auto');
      const sbomResult = await generateSBOM(targetFolder.uri.fsPath, {
        format: defaultFormat,
        preferredGenerator: sbomGenerator,
      });
      const outputPath = ensureOutputDirectory(vscodeApi, targetFolder.uri.fsPath);

      const suffix = timestampSuffix();
      const rawSbomPath = path.join(outputPath, `sbom-raw-${suffix}.json`);
      writeJsonFile(rawSbomPath, sbomResult.normalized);

      const exportBaseName = defaultFormat === 'spdx' ? `sbom-spdx-${suffix}` : `sbom-cyclonedx-${suffix}`;
      const exportPath = path.join(outputPath, `${exportBaseName}${sbomResult.exportFileExtension}`);
      writeTextFile(exportPath, sbomResult.exportText);
      const htmlReportPath = path.join(outputPath, `sbom-report-${suffix}.html`);
      writeTextFile(htmlReportPath, buildSbomHtmlReport(sbomResult, targetFolder.uri.fsPath));

      await openResultFile(vscodeApi, htmlReportPath, 'SBOM Report');
      vscodeApi.window.showInformationMessage(t(vscodeApi, 'sbomGenerated', path.basename(exportPath)));
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
  if (!(await ensureSbomToolsInstalled(vscodeApi, targetFolder.uri.fsPath))) return;

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
      const sbomGenerator = config.get('sbomGenerator', 'auto');
      progress.report({ message: t(vscodeApi, 'Generating SBOM...') });
      const sbomResult = await generateSBOM(workspacePath, {
        format: defaultFormat,
        preferredGenerator: sbomGenerator,
      });
      const suffix = timestampSuffix();
      const rawSbomPath = path.join(outputPath, `sbom-raw-${suffix}.json`);
      writeJsonFile(rawSbomPath, sbomResult.normalized);
      const sbomExportBaseName = defaultFormat === 'spdx' ? `sbom-spdx-${suffix}` : `sbom-cyclonedx-${suffix}`;
      writeTextFile(path.join(outputPath, `${sbomExportBaseName}${sbomResult.exportFileExtension}`), sbomResult.exportText);
      const sbomHtmlReportPath = path.join(outputPath, `sbom-report-${suffix}.html`);
      writeTextFile(sbomHtmlReportPath, buildSbomHtmlReport(sbomResult, workspacePath));

      progress.report({ message: t(vscodeApi, 'Running vulnerability scan...') });
      const scanResult = await scanVulnerabilities(workspacePath, scannerPreference);
      const reportPath = path.join(outputPath, `vulnerability-report-${suffix}.json`);
      writeJsonFile(reportPath, scanResult);
      const htmlReportPath = path.join(outputPath, `vulnerability-report-${suffix}.html`);
      writeTextFile(htmlReportPath, buildVulnerabilityHtmlReport(scanResult, workspacePath));

      const summary = formatVulnerabilitySummary(scanResult);
      await openResultFile(vscodeApi, sbomHtmlReportPath, 'SBOM Report');
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

async function setSbomGenerator(vscodeApi) {
  const config = vscodeApi.workspace.getConfiguration('sbomTool');
  const selected = await vscodeApi.window.showQuickPick(
    [
      { label: 'auto', description: 'Syft first, then Trivy, then built-in manifest parser' },
      { label: 'syft', description: 'Use Syft only for broad SBOM generation' },
      { label: 'trivy', description: 'Use Trivy only for filesystem SBOM generation' },
      { label: 'manifest', description: 'Use built-in package manifest parsing only' },
    ],
    { title: t(vscodeApi, 'sbomGeneratorSelectionTitle') }
  );

  if (!selected) return;
  await config.update('sbomGenerator', selected.label, vscodeApi.ConfigurationTarget.Workspace);
  vscodeApi.window.showInformationMessage(t(vscodeApi, 'sbomGeneratorUpdated', selected.label));
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
