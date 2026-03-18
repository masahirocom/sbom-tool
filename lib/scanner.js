const fs = require('node:fs');
const path = require('node:path');
const { exec, execSync } = require('node:child_process');
const { promisify } = require('node:util');
const { escapeHtml, isCommandAvailableAsync } = require('./common');
const { generateUUID, normalizeVersion, buildPurl, createEmptyNormalizedSbom, createDependencyMap, generateManifestSbom, collectCycloneDxLicenses, normalizeCycloneDxSbom, collectSpdxLicenses, findSpdxPurl, normalizeSpdxSbom } = require('./sbom/normalizer');

const execAsync = promisify(exec);

function detectCommandVersion(versionCommand, versionPattern) {
  try {
    const output = execSync(versionCommand, { encoding: 'utf-8' });
    const match = output.match(versionPattern);
    return match ? match[1] : undefined;
  } catch {
    return undefined;
  }
}

function detectTrivyVersion() {
  return detectCommandVersion('trivy --version', /Version:\s*(\d+\.\d+\.\d+)/i);
}

function detectSyftVersion() {
  return detectCommandVersion('syft version', /Version:\s*(\d+\.\d+\.\d+)/i);
}

function exportSBOMAsCycloneDxJson(sbom) {
  const projectRef = sbom.metadata.projectPurl || `${sbom.metadata.projectName}@${sbom.metadata.projectVersion}`;
  const dependencyMap = createDependencyMap(sbom.dependencies || []);
  const rootDependsOn = sbom.components
    .filter((component) => component.isDirect)
    .map((component) => component.id || component.purl || `${component.name}@${component.version}`);

  const cycloneDx = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    serialNumber: `urn:uuid:${generateUUID()}`,
    version: 1,
    metadata: {
      timestamp: sbom.metadata.timestamp,
      tools: [
        {
          vendor: 'SBOM Vulnerability Scanner',
          name: 'SBOM Generator',
          version: sbom.metadata.toolVersion || '1.1',
        },
      ],
      component: sbom.metadata.projectName
        ? {
            type: 'application',
            name: sbom.metadata.projectName,
            version: sbom.metadata.projectVersion,
            'bom-ref': projectRef,
          }
        : undefined,
    },
    components: sbom.components.map((component) => ({
      type: component.type,
      name: component.name,
      version: component.version,
      purl: component.purl,
      scope: component.scope || (component.isDev ? 'excluded' : 'required'),
      'bom-ref': component.id || component.purl || `${component.name}@${component.version}`,
      licenses: Array.isArray(component.licenses) && component.licenses.length > 0
        ? component.licenses.map((licenseValue) => ({ license: { name: licenseValue } }))
        : undefined,
    })),
    dependencies: [
      { ref: projectRef, dependsOn: rootDependsOn },
      ...Array.from(dependencyMap.entries()).map(([ref, dependsOn]) => ({ ref, dependsOn })),
    ],
  };

  return JSON.stringify(cycloneDx, null, 2);
}

function exportSBOMAsSpdx(sbom) {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'DataLicense: CC0-1.0',
    'SPDXID: SPDXRef-DOCUMENT',
    `DocumentName: ${sbom.metadata.projectName || 'Project'}`,
    `DocumentNamespace: https://sbom-vulnerability-scanner/${generateUUID()}`,
    `Creator: Tool: SBOM-Vulnerability-Scanner-${sbom.metadata.toolVersion || '1.1'}`,
    `Created: ${sbom.metadata.timestamp}`,
    '',
    `PackageName: ${sbom.metadata.projectName || 'unknown'}`,
    'SPDXID: SPDXRef-RootPackage',
    'PackageDownloadLocation: NOASSERTION',
    'FilesAnalyzed: false',
    '',
  ];

  sbom.components.forEach((component, index) => {
    lines.push(`PackageName: ${component.name}`);
    lines.push(`SPDXID: SPDXRef-Package-${index}`);
    lines.push(`PackageVersion: ${component.version}`);
    lines.push(`PackageDownloadLocation: ${component.purl || 'NOASSERTION'}`);
    lines.push(`FilesAnalyzed: false`);
    if (Array.isArray(component.licenses) && component.licenses.length > 0) {
      lines.push(`PackageLicenseDeclared: ${component.licenses.join(' AND ')}`);
    }
    lines.push('');
  });

  return lines.join('\n');
}

async function runSyftSbom(repoPath, requestedFormat) {
  const nativeFormat = requestedFormat === 'spdx' ? 'spdx-json' : 'cyclonedx-json';
  const command = `syft "${repoPath}" -o ${nativeFormat}`;
  const { stdout } = await execAsync(command, { maxBuffer: 100 * 1024 * 1024 });
  const document = JSON.parse(stdout);
  const normalized = nativeFormat === 'spdx-json'
    ? normalizeSpdxSbom(document, repoPath, {
        sbomGenerator: 'syft',
        generatorVersion: detectSyftVersion(),
        nativeFormat,
      })
    : normalizeCycloneDxSbom(document, repoPath, {
        sbomGenerator: 'syft',
        generatorVersion: detectSyftVersion(),
        nativeFormat,
      });

  return {
    normalized,
    exportText: JSON.stringify(document, null, 2),
    exportFormat: nativeFormat,
    exportFileExtension: '.json',
    generator: 'syft',
  };
}

async function runTrivySbom(repoPath, requestedFormat) {
  const nativeFormat = requestedFormat === 'spdx' ? 'spdx-json' : 'cyclonedx';
  const command = `trivy fs --format ${nativeFormat} --quiet "${repoPath}"`;
  const { stdout } = await execAsync(command, { maxBuffer: 100 * 1024 * 1024 });
  const document = JSON.parse(stdout);
  const normalized = nativeFormat === 'spdx-json'
    ? normalizeSpdxSbom(document, repoPath, {
        sbomGenerator: 'trivy',
        generatorVersion: detectTrivyVersion(),
        nativeFormat,
      })
    : normalizeCycloneDxSbom(document, repoPath, {
        sbomGenerator: 'trivy',
        generatorVersion: detectTrivyVersion(),
        nativeFormat,
      });

  return {
    normalized,
    exportText: JSON.stringify(document, null, 2),
    exportFormat: nativeFormat,
    exportFileExtension: '.json',
    generator: 'trivy',
  };
}

async function generateSBOM(repoPath, options = {}) {
  const requestedFormat = options.format === 'spdx' ? 'spdx' : 'cyclonedx-json';
  const preferredGenerator = String(options.preferredGenerator || 'auto');
  let candidates = ['syft', 'trivy', 'manifest'];
  if (preferredGenerator === 'syft') {
    candidates = ['syft'];
  } else if (preferredGenerator === 'trivy') {
    candidates = ['trivy'];
  } else if (preferredGenerator === 'manifest') {
    candidates = ['manifest'];
  }

  const errors = [];

  for (const candidate of candidates) {
    try {
      if (candidate === 'syft') {
        if (!(await isCommandAvailableAsync('syft'))) {
          throw new Error('syft command not found');
        }
        return await runSyftSbom(repoPath, requestedFormat);
      }

      if (candidate === 'trivy') {
        if (!(await isCommandAvailableAsync('trivy'))) {
          throw new Error('trivy command not found');
        }
        return await runTrivySbom(repoPath, requestedFormat);
      }

      const normalized = generateManifestSbom(repoPath);
      normalized.metadata.warning = 'Fallback manifest mode was used. Install Syft or Trivy for broader ecosystem coverage.';
      return {
        normalized,
        exportText: requestedFormat === 'spdx' ? exportSBOMAsSpdx(normalized) : exportSBOMAsCycloneDxJson(normalized),
        exportFormat: requestedFormat === 'spdx' ? 'spdx' : 'cyclonedx-json',
        exportFileExtension: requestedFormat === 'spdx' ? '.spdx' : '.json',
        generator: 'manifest',
      };
    } catch (error) {
      errors.push(`${candidate}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  throw new Error(`SBOM generation failed. ${errors.join(' / ')}`);
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

  function extractCveId(...values) {
    for (const value of values) {
      const text = String(value || '');
      const match = text.match(/CVE-\d{4}-\d+/i);
      if (match) {
        return match[0].toUpperCase();
      }
    }
    return '';
  }

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
            cveId: extractCveId(viaItem.cve, viaItem.title, viaItem.url, viaItem.name),
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

  const findingSeverity = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    info: 0,
  };

  for (const vulnerability of vulnerabilities) {
    if (vulnerability.severity === 'critical') findingSeverity.critical += 1;
    else if (vulnerability.severity === 'high') findingSeverity.high += 1;
    else if (vulnerability.severity === 'medium') findingSeverity.moderate += 1;
    else if (vulnerability.severity === 'low') findingSeverity.low += 1;
    else findingSeverity.info += 1;
  }

  const findingCount = vulnerabilities.length;
  const affectedPackages = metadata.total || 0;

  return {
    timestamp: new Date().toISOString(),
    source: 'npm-audit',
    totalVulnerabilities: findingCount,
    critical: findingSeverity.critical,
    high: findingSeverity.high,
    moderate: findingSeverity.moderate,
    low: findingSeverity.low,
    info: findingSeverity.info,
    vulnerabilities,
    fixable: fixablePackages.size,
    affectedPackages,
    summary: formatSummaryCounts(
      findingCount,
      findingSeverity.critical,
      findingSeverity.high,
      findingSeverity.moderate,
      findingSeverity.low,
      fixablePackages.size,
      affectedPackages
    ),
  };
}



async function checkProjectEnvironment(repoPath) {
  const packageJsonExists = fs.existsSync(path.join(repoPath, 'package.json'));
  const packageLockExists = fs.existsSync(path.join(repoPath, 'package-lock.json'));
  const brewAvailable = await isCommandAvailableAsync('brew');
  const syftAvailable = await isCommandAvailableAsync('syft');
  const trivyAvailable = await isCommandAvailableAsync('trivy');
  const npmAvailable = await isCommandAvailableAsync('npm');

  return {
    packageJsonExists,
    packageLockExists,
    brewAvailable,
    syftAvailable,
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
  function findNpmAuditTargetPath(basePath) {
    const rootPackageJsonPath = path.join(basePath, 'package.json');
    if (fs.existsSync(rootPackageJsonPath)) {
      return { targetPath: basePath, packageJsonFound: true, autoDiscovered: false };
    }

    // Monorepo-friendly fallback: scan common folders first.
    const preferredRoots = ['packages', 'apps'];
    for (const root of preferredRoots) {
      const rootPath = path.join(basePath, root);
      if (!fs.existsSync(rootPath)) continue;

      const children = fs.readdirSync(rootPath, { withFileTypes: true });
      for (const child of children) {
        if (!child.isDirectory()) continue;
        const candidatePath = path.join(rootPath, child.name);
        if (fs.existsSync(path.join(candidatePath, 'package.json'))) {
          return { targetPath: candidatePath, packageJsonFound: true, autoDiscovered: true };
        }
      }
    }

    return { targetPath: basePath, packageJsonFound: false, autoDiscovered: false };
  }

  const auditTarget = findNpmAuditTargetPath(repoPath);
  if (!auditTarget.packageJsonFound) {
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
      summary: `package.json not found under scan target: ${repoPath}. Node.js dependency vulnerability scan was skipped.`,
    };
  }

  const command = `cd "${auditTarget.targetPath}" && npm audit --json --package-lock-only`;
  const packageLockPath = path.join(auditTarget.targetPath, 'package-lock.json');
  const prepareLockCommand = `cd "${auditTarget.targetPath}" && npm install --package-lock-only --ignore-scripts --no-audit --fund=false`;

  function parseAuditJson(raw) {
    if (!raw) {
      return null;
    }

    try {
      return JSON.parse(raw);
    } catch {
      const firstBrace = raw.indexOf('{');
      const lastBrace = raw.lastIndexOf('}');
      if (firstBrace >= 0 && lastBrace > firstBrace) {
        const jsonCandidate = raw.slice(firstBrace, lastBrace + 1);
        try {
          return JSON.parse(jsonCandidate);
        } catch {
          return null;
        }
      }
      return null;
    }
  }

  function buildFailureSummary(errorOutput) {
    const normalized = String(errorOutput || '');

    if (!fs.existsSync(packageLockPath) || normalized.includes('ENOLOCK')) {
      return 'npm audit requires package-lock.json. Run npm install once in the target project, or switch scanner to Trivy.';
    }

    if (normalized.includes('command not found') || normalized.includes('npm: not found')) {
      return 'npm command not found in runtime environment. Install Node.js/npm or switch scanner to Trivy.';
    }

    if (normalized.includes('EAI_AGAIN') || normalized.includes('ECONNREFUSED') || normalized.includes('ENOTFOUND')) {
      return 'npm registry network access failed. Check internet/proxy settings and retry.';
    }

    const firstLine = normalized
      .split('\n')
      .map((line) => line.trim())
      .find((line) => line.length > 0);

    return firstLine
      ? `npm audit failed: ${firstLine}`
      : 'npm audit failed. Please verify dependency installation state.';
  }

  function tryParseFromStreams(...streams) {
    for (const stream of streams) {
      const parsed = parseAuditJson(stream);
      if (parsed) {
        return parsed;
      }
    }
    return null;
  }

  async function ensurePackageLockExists() {
    if (fs.existsSync(packageLockPath)) {
      return { prepared: false };
    }

    try {
      await execAsync(prepareLockCommand, { maxBuffer: 100 * 1024 * 1024 });
      return { prepared: fs.existsSync(packageLockPath) };
    } catch (error) {
      return {
        prepared: false,
        error,
      };
    }
  }

  const prepareResult = await ensurePackageLockExists();

  try {
    const { stdout, stderr } = await execAsync(command, { maxBuffer: 100 * 1024 * 1024 });
    const auditData = tryParseFromStreams(stdout, stderr);
    if (!auditData) {
      throw new Error('npm audit returned non-JSON output.');
    }
    const parsed = parseNpmAuditResult(auditData);
    if (auditTarget.autoDiscovered) {
      parsed.summary = `${parsed.summary} (npm audit target: ${auditTarget.targetPath})`;
    }
    return parsed;
  } catch (error) {
    const stdout = error && error.stdout ? String(error.stdout) : '';
    const stderr = error && error.stderr ? String(error.stderr) : '';
    const auditData = tryParseFromStreams(stdout, stderr);
    if (auditData) {
      return parseNpmAuditResult(auditData);
    }

    let summary = buildFailureSummary(`${stderr}\n${stdout}`);
    if (!fs.existsSync(packageLockPath) && prepareResult.error) {
      const prepareErrorMessage =
        prepareResult.error instanceof Error ? prepareResult.error.message : String(prepareResult.error);
      summary = `Auto-prepare failed while generating package-lock.json: ${prepareErrorMessage}`;
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
      summary,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function scanVulnerabilities(repoPath, scannerPreference = 'auto') {
  const scanner = String(scannerPreference || 'auto');

  if (scanner === 'trivy') {
    const trivyAvailable = await isCommandAvailableAsync('trivy');
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

function formatSummaryCounts(total, critical, high, moderate, low, fixable, affectedPackages) {
  if (total === 0) {
    return 'No vulnerabilities detected.';
  }

  const parts = [];
  if (critical > 0) parts.push(`Critical:${critical}`);
  if (high > 0) parts.push(`High:${high}`);
  if (moderate > 0) parts.push(`Moderate:${moderate}`);
  if (low > 0) parts.push(`Low:${low}`);

  const fixableText = fixable > 0 ? `Fixable packages:${fixable}` : 'Fixable packages:0';
  const packageText =
    typeof affectedPackages === 'number' ? ` / Affected packages:${affectedPackages}` : '';
  return `${total} findings (${parts.join(', ')})${packageText} / ${fixableText}`;
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
