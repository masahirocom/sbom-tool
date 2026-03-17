const vscode = require('vscode');
const path = require('node:path');
const fs = require('node:fs');
const {
  generateSBOM,
  exportSBOMAsCycloneDxJson,
  exportSBOMAsSpdx,
  scanVulnerabilities,
  formatVulnerabilitySummary,
} = require('./lib/scanner');

function t(vscodeApi, message, ...args) {
  if (vscodeApi.l10n && typeof vscodeApi.l10n.t === 'function') {
    return vscodeApi.l10n.t(message, ...args);
  }
  return message.replace(/\{(\d+)\}/g, (_, index) => String(args[Number(index)] ?? ''));
}

function activate(context) {
  const generateSbomCommand = vscode.commands.registerCommand('sbomTool.generateSbom', async () => {
    await runGenerateSbom(vscode);
  });

  const scanVulnerabilityCommand = vscode.commands.registerCommand('sbomTool.scanVulnerabilities', async () => {
    await runVulnerabilityScan(vscode);
  });

  const generateAndScanCommand = vscode.commands.registerCommand('sbomTool.generateAndScan', async () => {
    await runGenerateAndScan(vscode);
  });

  context.subscriptions.push(generateSbomCommand, scanVulnerabilityCommand, generateAndScanCommand);
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

function timestampSuffix() {
  return new Date().toISOString().replace(/[:.]/g, '-');
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

      const message = t(vscodeApi, 'SBOM generated: {0}', path.basename(exportPath));
      const openAction = t(vscodeApi, 'Open output folder');
      const selected = await vscodeApi.window.showInformationMessage(message, openAction);
      if (selected === openAction) {
        await vscodeApi.commands.executeCommand('revealFileInOS', vscodeApi.Uri.file(outputPath));
      }
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
      const reportPath = path.join(outputPath, `vulnerability-report-${timestampSuffix()}.json`);
      writeJsonFile(reportPath, scanResult);

      const summary = formatVulnerabilitySummary(scanResult);
      const openAction = t(vscodeApi, 'Open report');
      const selected = await vscodeApi.window.showInformationMessage(summary, openAction);
      if (selected === openAction) {
        const document = await vscodeApi.workspace.openTextDocument(vscodeApi.Uri.file(reportPath));
        await vscodeApi.window.showTextDocument(document, { preview: false });
      }
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

      const summary = formatVulnerabilitySummary(scanResult);
      const openAction = t(vscodeApi, 'Open output folder');
      const selected = await vscodeApi.window.showInformationMessage(t(vscodeApi, 'Done: {0}', summary), openAction);
      if (selected === openAction) {
        await vscodeApi.commands.executeCommand('revealFileInOS', vscodeApi.Uri.file(outputPath));
      }
    }
  );
}

module.exports = {
  activate,
  deactivate,
};
