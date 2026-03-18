const fs = require('node:fs');
const path = require('node:path');
const { isCommandAvailableAsync } = require('./common');
const {
  generateUUID,
  createDependencyMap,
  generateManifestSbom,
  normalizeCycloneDxSbom,
  normalizeSpdxSbom,
} = require('./sbom/normalizer');
const {
  formatVulnerabilitySummary,
  parseTrivyResult,
  parseNpmAuditResult,
} = require('./vulnerability/parser');
const {
  detectTrivyVersion,
  detectSyftVersion,
  runSyftSbomCommand,
  runTrivySbomCommand,
  runTrivyScanCommand,
  runNpmAuditCommand,
  prepareNpmPackageLock,
} = require('./tool/executor');

function exportSBOMAsCycloneDxJson(sbom) {
  const projectRef = sbom.metadata.projectPurl || `${sbom.metadata.projectName}@${sbom.metadata.projectVersion}`;
  const dependencyMap = createDependencyMap(sbom.dependencies || []);
  const rootDependsOn = sbom.components
    .filter((component) => component.isDirect)
    .map((component) => component.id || component.purl || `${component.name}@${component.version}`);

  return JSON.stringify({
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
  }, null, 2);
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
    lines.push(
      `PackageName: ${component.name}`,
      `SPDXID: SPDXRef-Package-${index}`,
      `PackageVersion: ${component.version}`,
      `PackageDownloadLocation: ${component.purl || 'NOASSERTION'}`,
      'FilesAnalyzed: false'
    );
    if (Array.isArray(component.licenses) && component.licenses.length > 0) {
      lines.push(`PackageLicenseDeclared: ${component.licenses.join(' AND ')}`);
    }
    lines.push('');
  });

  return lines.join('\n');
}

function resolveSbomCandidates(preferredGenerator) {
  if (preferredGenerator === 'syft') {
    return ['syft'];
  }
  if (preferredGenerator === 'trivy') {
    return ['trivy'];
  }
  if (preferredGenerator === 'manifest') {
    return ['manifest'];
  }
  return ['syft', 'trivy', 'manifest'];
}

function buildManifestResult(repoPath, requestedFormat) {
  const normalized = generateManifestSbom(repoPath);
  normalized.metadata.warning = 'Fallback manifest mode was used. Install Syft or Trivy for broader ecosystem coverage.';

  return {
    normalized,
    exportText: requestedFormat === 'spdx' ? exportSBOMAsSpdx(normalized) : exportSBOMAsCycloneDxJson(normalized),
    exportFormat: requestedFormat === 'spdx' ? 'spdx' : 'cyclonedx-json',
    exportFileExtension: requestedFormat === 'spdx' ? '.spdx' : '.json',
    generator: 'manifest',
  };
}

async function runSyftSbom(repoPath, requestedFormat) {
  const nativeFormat = requestedFormat === 'spdx' ? 'spdx-json' : 'cyclonedx-json';
  const { stdout } = await runSyftSbomCommand(repoPath, nativeFormat);
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
  const { stdout } = await runTrivySbomCommand(repoPath, nativeFormat);
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

async function generateSbomFromCandidate(candidate, repoPath, requestedFormat) {
  if (candidate === 'syft') {
    if (!(await isCommandAvailableAsync('syft'))) {
      throw new Error('syft command not found');
    }
    return runSyftSbom(repoPath, requestedFormat);
  }

  if (candidate === 'trivy') {
    if (!(await isCommandAvailableAsync('trivy'))) {
      throw new Error('trivy command not found');
    }
    return runTrivySbom(repoPath, requestedFormat);
  }

  return buildManifestResult(repoPath, requestedFormat);
}

async function generateSBOM(repoPath, options = {}) {
  const requestedFormat = options.format === 'spdx' ? 'spdx' : 'cyclonedx-json';
  const preferredGenerator = String(options.preferredGenerator || 'auto');
  const candidates = resolveSbomCandidates(preferredGenerator);
  const errors = [];

  for (const candidate of candidates) {
    try {
      return await generateSbomFromCandidate(candidate, repoPath, requestedFormat);
    } catch (error) {
      errors.push(`${candidate}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  throw new Error(`SBOM generation failed. ${errors.join(' / ')}`);
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
  const { stdout } = await runTrivyScanCommand(repoPath);
  return parseTrivyResult(JSON.parse(stdout));
}

function findNpmAuditTargetPath(basePath) {
  const rootPackageJsonPath = path.join(basePath, 'package.json');
  if (fs.existsSync(rootPackageJsonPath)) {
    return { targetPath: basePath, packageJsonFound: true, autoDiscovered: false };
  }

  for (const root of ['packages', 'apps']) {
    const rootPath = path.join(basePath, root);
    if (!fs.existsSync(rootPath)) {
      continue;
    }

    const children = fs.readdirSync(rootPath, { withFileTypes: true });
    for (const child of children) {
      if (!child.isDirectory()) {
        continue;
      }

      const candidatePath = path.join(rootPath, child.name);
      if (fs.existsSync(path.join(candidatePath, 'package.json'))) {
        return { targetPath: candidatePath, packageJsonFound: true, autoDiscovered: true };
      }
    }
  }

  return { targetPath: basePath, packageJsonFound: false, autoDiscovered: false };
}

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
      try {
        return JSON.parse(raw.slice(firstBrace, lastBrace + 1));
      } catch {
        return null;
      }
    }
    return null;
  }
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

function buildNpmAuditFailureSummary(errorOutput, packageLockPath) {
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

function createEmptyScanResult(summary, error) {
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
    ...(error ? { error } : {}),
  };
}

async function ensureAuditPackageLock(auditTarget, packageLockPath) {
  if (fs.existsSync(packageLockPath)) {
    return undefined;
  }

  try {
    await prepareNpmPackageLock(auditTarget.targetPath);
    return undefined;
  } catch (error) {
    return error;
  }
}

function buildNpmAuditErrorResult(error, packageLockPath, prepareError) {
  const stdout = String(error?.stdout || '');
  const stderr = String(error?.stderr || '');
  const auditData = tryParseFromStreams(stdout, stderr);
  if (auditData) {
    return parseNpmAuditResult(auditData);
  }

  let summary = buildNpmAuditFailureSummary(`${stderr}\n${stdout}`, packageLockPath);
  if (!fs.existsSync(packageLockPath) && prepareError) {
    const prepareErrorMessage = prepareError instanceof Error ? prepareError.message : String(prepareError);
    summary = `Auto-prepare failed while generating package-lock.json: ${prepareErrorMessage}`;
  }

  return createEmptyScanResult(summary, error instanceof Error ? error.message : String(error));
}

async function runNpmAudit(repoPath) {
  const auditTarget = findNpmAuditTargetPath(repoPath);
  if (!auditTarget.packageJsonFound) {
    return createEmptyScanResult(
      `package.json not found under scan target: ${repoPath}. Node.js dependency vulnerability scan was skipped.`
    );
  }

  const packageLockPath = path.join(auditTarget.targetPath, 'package-lock.json');
  const prepareError = await ensureAuditPackageLock(auditTarget, packageLockPath);

  try {
    const { stdout, stderr } = await runNpmAuditCommand(auditTarget.targetPath);
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
    return buildNpmAuditErrorResult(error, packageLockPath, prepareError);
  }
}

async function scanVulnerabilities(repoPath, scannerPreference = 'auto') {
  const scanner = String(scannerPreference || 'auto');

  if (scanner === 'trivy') {
    if (!(await isCommandAvailableAsync('trivy'))) {
      throw new Error('Trivyが見つかりません。trivyをインストールするか、scanner設定をauto/npm-auditに変更してください。');
    }
    return runTrivyScan(repoPath);
  }

  if (scanner === 'npm-audit') {
    return runNpmAudit(repoPath);
  }

  if (await isCommandAvailableAsync('trivy')) {
    try {
      return await runTrivyScan(repoPath);
    } catch {
    }
  }

  return runNpmAudit(repoPath);
}

module.exports = {
  generateSBOM,
  exportSBOMAsCycloneDxJson,
  exportSBOMAsSpdx,
  checkProjectEnvironment,
  scanVulnerabilities,
  formatVulnerabilitySummary,
};

