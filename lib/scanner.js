const fs = require('node:fs');
const path = require('node:path');
const { exec, execSync } = require('node:child_process');
const { promisify } = require('node:util');

const execAsync = promisify(exec);

function detectTrivyVersion() {
  try {
    const output = execSync('trivy --version', { encoding: 'utf-8' });
    const match = output.match(/Version:\s*([0-9]+\.[0-9]+\.[0-9]+)/i);
    return match ? match[1] : undefined;
  } catch {
    return undefined;
  }
}

function normalizeVersion(version) {
  return String(version).replace(/^[\^~>=<\s]+/, '').split(/\s+/)[0];
}

function generateSBOM(repoPath) {
  const components = [];
  const dependencies = [];
  const trivyVersion = detectTrivyVersion();

  const packageJsonPath = path.join(repoPath, 'package.json');
  let packageJson = {};

  try {
    const content = fs.readFileSync(packageJsonPath, 'utf-8');
    packageJson = JSON.parse(content);
  } catch {
    return {
      version: '1.0',
      format: 'CycloneDX',
      components,
      dependencies,
      metadata: {
        timestamp: new Date().toISOString(),
        toolName: 'SBOM Tool',
        toolVersion: '1.0',
        trivyVersion,
      },
    };
  }

  const allDeps = {
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {}),
    ...(packageJson.optionalDependencies || {}),
  };

  for (const [name, version] of Object.entries(allDeps)) {
    const normalizedVersion = normalizeVersion(version);
    components.push({
      name,
      version: normalizedVersion,
      type: 'library',
      purl: `pkg:npm/${name}@${normalizedVersion}`,
      isDev: Boolean(packageJson.devDependencies && packageJson.devDependencies[name] !== undefined),
    });
  }

  const lockFilePath = path.join(repoPath, 'package-lock.json');
  try {
    const lockContent = fs.readFileSync(lockFilePath, 'utf-8');
    const lockJson = JSON.parse(lockContent);

    if (lockJson.packages) {
      for (const [depPath, depInfo] of Object.entries(lockJson.packages)) {
        if (depPath === '' || !depInfo || !depInfo.name) continue;

        if (components.find((component) => component.name === depInfo.name && component.version === depInfo.version)) {
          continue;
        }

        components.push({
          name: depInfo.name,
          version: depInfo.version,
          type: 'library',
          purl: `pkg:npm/${depInfo.name}@${depInfo.version}`,
          isDev: false,
          isTransitive: true,
        });

        if (depInfo.requires) {
          for (const [depName, depVersion] of Object.entries(depInfo.requires)) {
            dependencies.push({
              name: depInfo.name,
              dependsOn: depName,
              version: depVersion,
            });
          }
        }
      }
    }
  } catch {
  }

  components.sort((a, b) => a.name.localeCompare(b.name));

  return {
    version: '1.0',
    format: 'CycloneDX',
    components,
    dependencies,
    metadata: {
      timestamp: new Date().toISOString(),
      projectName: packageJson.name || 'unknown',
      projectVersion: packageJson.version || 'unknown',
      toolName: 'SBOM Tool',
      toolVersion: '1.0',
      trivyVersion,
    },
  };
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (char) => {
    const random = (Math.random() * 16) | 0;
    const value = char === 'x' ? random : (random & 0x3) | 0x8;
    return value.toString(16);
  });
}

function exportSBOMAsCycloneDxJson(sbom) {
  const cycloneDx = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    serialNumber: `urn:uuid:${generateUUID()}`,
    version: 1,
    metadata: {
      timestamp: sbom.metadata.timestamp,
      tools: [
        {
          vendor: 'SBOM Tool',
          name: 'SBOM Generator',
          version: '1.0',
        },
      ],
      component: sbom.metadata.projectName
        ? {
            type: 'application',
            name: sbom.metadata.projectName,
            version: sbom.metadata.projectVersion,
          }
        : undefined,
    },
    components: sbom.components.map((component) => ({
      type: component.type,
      name: component.name,
      version: component.version,
      purl: component.purl,
      scope: component.isDev ? 'excluded' : 'required',
    })),
  };

  return JSON.stringify(cycloneDx, null, 2);
}

function exportSBOMAsSpdx(sbom) {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'DataLicense: CC0-1.0',
    'SPDXID: SPDXRef-DOCUMENT',
    `DocumentName: ${sbom.metadata.projectName || 'Project'}`,
    `DocumentNamespace: https://sbom-tool/${generateUUID()}`,
    'Creator: Tool: SBOM-Tool-1.0',
    `Created: ${sbom.metadata.timestamp}`,
    '',
    `PackageName: ${sbom.metadata.projectName || 'unknown'}`,
    'SPDXID: SPDXRef-Package',
    'PackageDownloadLocation: NOASSERTION',
    'FilesAnalyzed: false',
    'PackageVerificationCode: 0000000000000000000000000000000000000000 ()',
    '',
  ];

  sbom.components.forEach((component, index) => {
    lines.push(`PackageName: ${component.name}`);
    lines.push(`SPDXID: SPDXRef-Package-${index}`);
    lines.push(`PackageVersion: ${component.version}`);
    lines.push(`PackageDownloadLocation: ${component.purl || 'NOASSERTION'}`);
    lines.push('FilesAnalyzed: false');
    lines.push('PackageVerificationCode: 0000000000000000000000000000000000000000 ()');
    lines.push('');
  });

  return lines.join('\n');
}

function mapSeverity(severity) {
  switch (String(severity || '').toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'info';
  }
}

function parseTrivyResult(trivyData) {
  const vulnerabilities = [];
  let critical = 0;
  let high = 0;
  let moderate = 0;
  let low = 0;
  let info = 0;
  const fixablePackages = new Set();

  if (Array.isArray(trivyData.Results)) {
    for (const result of trivyData.Results) {
      if (!Array.isArray(result.Vulnerabilities)) continue;

      for (const vulnerability of result.Vulnerabilities) {
        const severity = mapSeverity(vulnerability.Severity);
        if (severity === 'critical') critical += 1;
        else if (severity === 'high') high += 1;
        else if (severity === 'medium') moderate += 1;
        else if (severity === 'low') low += 1;
        else info += 1;

        if (vulnerability.FixedVersion) {
          fixablePackages.add(vulnerability.PkgName);
        }

        let cvssScore;
        if (vulnerability.CVSS && typeof vulnerability.CVSS === 'object') {
          for (const vendorCvss of Object.values(vulnerability.CVSS)) {
            if (vendorCvss && vendorCvss.V3Score) {
              cvssScore = vendorCvss.V3Score;
              break;
            }
          }
        }

        vulnerabilities.push({
          packageName: vulnerability.PkgName,
          packagePath: result.Target,
          title: vulnerability.Title || vulnerability.VulnerabilityID,
          description: vulnerability.Description || 'No description available',
          severity,
          affectedRange: vulnerability.InstalledVersion,
          cwe: [],
          cvss: cvssScore,
          proposedFix: vulnerability.FixedVersion ? `Update to ${vulnerability.FixedVersion}` : 'No fix available',
          fixable: Boolean(vulnerability.FixedVersion),
          reference: vulnerability.PrimaryURL || (Array.isArray(vulnerability.References) ? vulnerability.References[0] : ''),
          currentVersion: vulnerability.InstalledVersion,
          fixedVersions: vulnerability.FixedVersion || '',
          cveId: vulnerability.VulnerabilityID,
          url: vulnerability.PrimaryURL || (Array.isArray(vulnerability.References) ? vulnerability.References[0] : ''),
        });
      }
    }
  }

  const total = critical + high + moderate + low + info;
  return {
    timestamp: new Date().toISOString(),
    source: 'trivy',
    totalVulnerabilities: total,
    critical,
    high,
    moderate,
    low,
    info,
    vulnerabilities,
    fixable: fixablePackages.size,
    summary: formatSummaryCounts(total, critical, high, moderate, low, fixablePackages.size),
  };
}

function parseNpmAuditResult(auditData) {
  const vulnerabilities = [];
  const fixablePackages = new Set();

  if (auditData.vulnerabilities && typeof auditData.vulnerabilities === 'object') {
    for (const [packagePath, vulnerabilityInfo] of Object.entries(auditData.vulnerabilities)) {
      const packageName = vulnerabilityInfo.name;
      const severity = mapSeverity(vulnerabilityInfo.severity);

      if (vulnerabilityInfo.fixAvailable) {
        fixablePackages.add(packageName);
      }

      if (Array.isArray(vulnerabilityInfo.via)) {
        for (const viaItem of vulnerabilityInfo.via) {
          if (!viaItem || typeof viaItem !== 'object') continue;

          vulnerabilities.push({
            packageName,
            packagePath,
            title: viaItem.title || 'Unknown vulnerability',
            description: viaItem.title || 'No description available',
            severity,
            affectedRange: vulnerabilityInfo.range,
            cwe: viaItem.cwe || [],
            cvss: viaItem.cvss && typeof viaItem.cvss === 'object' ? viaItem.cvss.score : undefined,
            proposedFix: vulnerabilityInfo.fixAvailable
              ? typeof vulnerabilityInfo.fixAvailable === 'boolean'
                ? 'Run npm audit fix'
                : 'Available update'
              : 'No fix available',
            fixable: Boolean(vulnerabilityInfo.fixAvailable),
            reference: viaItem.url || '',
          });
        }
      }
    }
  }

  const metadata = auditData.metadata && auditData.metadata.vulnerabilities
    ? auditData.metadata.vulnerabilities
    : {
        total: vulnerabilities.length,
        critical: 0,
        high: 0,
        moderate: 0,
        low: 0,
        info: 0,
      };

  return {
    timestamp: new Date().toISOString(),
    source: 'npm-audit',
    totalVulnerabilities: metadata.total || 0,
    critical: metadata.critical || 0,
    high: metadata.high || 0,
    moderate: metadata.moderate || 0,
    low: metadata.low || 0,
    info: metadata.info || 0,
    vulnerabilities,
    fixable: fixablePackages.size,
    summary: formatSummaryCounts(
      metadata.total || 0,
      metadata.critical || 0,
      metadata.high || 0,
      metadata.moderate || 0,
      metadata.low || 0,
      fixablePackages.size
    ),
  };
}

async function isCommandAvailable(command) {
  try {
    await execAsync(`which ${command}`);
    return true;
  } catch {
    return false;
  }
}

async function checkProjectEnvironment(repoPath) {
  const packageJsonExists = fs.existsSync(path.join(repoPath, 'package.json'));
  const packageLockExists = fs.existsSync(path.join(repoPath, 'package-lock.json'));
  const trivyAvailable = await isCommandAvailable('trivy');
  const npmAvailable = await isCommandAvailable('npm');

  return {
    packageJsonExists,
    packageLockExists,
    trivyAvailable,
    npmAvailable,
  };
}

async function runTrivyScan(repoPath) {
  const command = `trivy fs --format json --quiet "${repoPath}"`;
  const { stdout } = await execAsync(command, { maxBuffer: 50 * 1024 * 1024 });
  const trivyData = JSON.parse(stdout);
  return parseTrivyResult(trivyData);
}

async function runNpmAudit(repoPath) {
  const command = `cd "${repoPath}" && npm audit --json 2>&1`;
  try {
    const { stdout } = await execAsync(command, { maxBuffer: 20 * 1024 * 1024 });
    const auditData = JSON.parse(stdout);
    return parseNpmAuditResult(auditData);
  } catch (error) {
    if (error && error.stdout) {
      try {
        const auditData = JSON.parse(error.stdout);
        return parseNpmAuditResult(auditData);
      } catch {
      }
    }

    return {
      timestamp: new Date().toISOString(),
      source: 'npm-audit',
      totalVulnerabilities: 0,
      critical: 0,
      high: 0,
      moderate: 0,
      low: 0,
      info: 0,
      vulnerabilities: [],
      fixable: 0,
      summary: 'npm audit failed. Please verify dependency installation state.',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function scanVulnerabilities(repoPath, scannerPreference = 'auto') {
  const hasPackageJson = fs.existsSync(path.join(repoPath, 'package.json'));
  if (!hasPackageJson) {
    return {
      timestamp: new Date().toISOString(),
      source: scannerPreference === 'trivy' ? 'trivy' : 'npm-audit',
      totalVulnerabilities: 0,
      critical: 0,
      high: 0,
      moderate: 0,
      low: 0,
      info: 0,
      vulnerabilities: [],
      fixable: 0,
      summary: 'package.json not found. Node.js dependency vulnerability scan was skipped.',
    };
  }

  const scanner = String(scannerPreference || 'auto');

  if (scanner === 'trivy') {
    const trivyAvailable = await isCommandAvailable('trivy');
    if (!trivyAvailable) {
      throw new Error('Trivyが見つかりません。trivyをインストールするか、scanner設定をauto/npm-auditに変更してください。');
    }
    return runTrivyScan(repoPath);
  }

  if (scanner === 'npm-audit') {
    return runNpmAudit(repoPath);
  }

  const trivyAvailable = await isCommandAvailable('trivy');
  if (trivyAvailable) {
    try {
      return await runTrivyScan(repoPath);
    } catch {
    }
  }

  return runNpmAudit(repoPath);
}

function formatSummaryCounts(total, critical, high, moderate, low, fixable) {
  if (total === 0) {
    return 'No vulnerabilities detected.';
  }

  const parts = [];
  if (critical > 0) parts.push(`Critical:${critical}`);
  if (high > 0) parts.push(`High:${high}`);
  if (moderate > 0) parts.push(`Moderate:${moderate}`);
  if (low > 0) parts.push(`Low:${low}`);

  const fixableText = fixable > 0 ? `Fixable packages:${fixable}` : 'Fixable packages:0';
  return `${total} vulnerabilities (${parts.join(', ')}) / ${fixableText}`;
}

function formatVulnerabilitySummary(scanResult) {
  if (!scanResult) {
    return 'Could not retrieve vulnerability scan result.';
  }

  return `[${scanResult.source}] ${scanResult.summary}`;
}

module.exports = {
  generateSBOM,
  exportSBOMAsCycloneDxJson,
  exportSBOMAsSpdx,
  checkProjectEnvironment,
  scanVulnerabilities,
  formatVulnerabilitySummary,
};
