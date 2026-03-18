const fs = require('node:fs');
const path = require('node:path');

async function openResultFile(vscode, filePath, title) {
  const mode = vscode.workspace.getConfiguration('sbomTool').get('resultOpenMode', 'vscode');
  const fileUri = vscode.Uri.file(filePath);

  if (mode === 'external') {
    await vscode.env.openExternal(fileUri);
    return;
  }

  const extension = path.extname(filePath).toLowerCase();
  if (extension === '.html' || extension === '.htm') {
    const panel = vscode.window.createWebviewPanel(
      'sbomToolReport',
      title || 'SBOM Vulnerability Scanner Report',
      vscode.ViewColumn.Active,
      { enableScripts: true }
    );
    panel.webview.html = fs.readFileSync(filePath, 'utf-8');
    return;
  }

  const document = await vscode.workspace.openTextDocument(fileUri);
  await vscode.window.showTextDocument(document, {
    preview: false,
    viewColumn: vscode.ViewColumn.Active,
  });
}

module.exports = {
  openResultFile,
};
