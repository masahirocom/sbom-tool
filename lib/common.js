const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');
const { promisify } = require('node:util');
const { exec } = require('node:child_process');

const execAsync = promisify(exec);

/**
 * HTML特殊文字をエスケープ
 * @param {any} value - エスケープする値
 * @returns {string} エスケープされた文字列
 */
function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * タイムスタンプサフィックスを生成（ファイル名用）
 * @returns {string} ISO形式のタイムスタンプサフィックス
 */
function timestampSuffix() {
  return new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-');
}

/**
 * 出力ディレクトリ内のファイルリストを取得
 * @param {string} outputPath - 出力ディレクトリパス
 * @returns {Array<{name: string, fullPath: string, mtimeMs: number}>} ファイル情報の配列
 */
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

/**
 * JSONファイルに書き込み
 * @param {string} filePath - ファイルパス
 * @param {any} data - 書き込むデータ
 */
function writeJsonFile(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

/**
 * テキストファイルに書き込み
 * @param {string} filePath - ファイルパス
 * @param {string} text - 書き込むテキスト
 */
function writeTextFile(filePath, text) {
  fs.writeFileSync(filePath, text, 'utf-8');
}

/**
 * コマンドが利用可能か確認（同期版）
 * @param {string} command - コマンド名
 * @returns {boolean} 利用可能な場合true
 */
function isCommandAvailable(command) {
  try {
    const checkCommand = process.platform === 'win32' ? `where ${command}` : `which ${command}`;
    execSync(checkCommand, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * コマンドが利用可能か確認（非同期版）
 * @param {string} command - コマンド名
 * @returns {Promise<boolean>} 利用可能な場合true
 */
async function isCommandAvailableAsync(command) {
  try {
    const checkCommand = process.platform === 'win32' ? `where ${command}` : `which ${command}`;
    await execAsync(checkCommand);
    return true;
  } catch {
    return false;
  }
}

/**
 * 結果ファイルグループキーを取得
 * @param {string} fileName - ファイル名
 * @returns {string} グループキー
 */
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

module.exports = {
  escapeHtml,
  timestampSuffix,
  listResultFiles,
  writeJsonFile,
  writeTextFile,
  isCommandAvailable,
  isCommandAvailableAsync,
  getGroupKey,
};
