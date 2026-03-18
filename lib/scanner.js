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

