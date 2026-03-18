const path = require('node:path');
const { escapeHtml } = require('../common');

/**
 * コンポーネントのスコープを説明する文字列を返す
 * @param {Object} component - コンポーネント情報
 * @returns {string} スコープ説明文字列
 */
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

/**
 * SBOM HTML レポートを生成
 * @param {Object} sbomResult - SBOM生成結果
 * @param {string} workspacePath - ワークスペースパス
 * @returns {string} HTML文字列
 */
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

/**
 * セーフなHTMLリンク要素を生成
 * @param {string} url - URL
 * @param {string} label - リンクテキスト
 * @returns {string} HTMLリンク要素、またはURLが無効な場合は空文字列
 */
function toSafeLink(url, label) {
  const value = String(url || '').trim();
  if (!/^https?:\/\//i.test(value)) {
    return '';
  }
  return `<a href="${escapeHtml(value)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label || value)}</a>`;
}

/**
 * 脆弱性レポート内の参照セル（CVE/GHSA）を構築
 * @param {Object} item - 脆弱性情報
 * @returns {string} HTMLセル内容
 */
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

/**
 * 脆弱性 HTML レポートを生成
 * @param {Object} scanResult - スキャン結果
 * @param {string} workspacePath - ワークスペースパス
 * @returns {string} HTML文字列
 */
function buildVulnerabilityHtmlReport(scanResult, workspacePath) {
  const title = `Vulnerability Report - ${path.basename(workspacePath)}`;

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

module.exports = {
  describeComponentScope,
  buildSbomHtmlReport,
  buildVulnerabilityHtmlReport,
};
