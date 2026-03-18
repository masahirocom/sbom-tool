const fs = require('node:fs');
const path = require('node:path');

/**
 * バージョン文字列を正規化
 * @param {string} version - バージョン文字列
 * @returns {string} 正規化されたバージョン
 */
function normalizeVersion(version) {
  return String(version).replace(/^[\^~>=<\s]+/, '').split(/\s+/)[0];
}

/**
 * Package URL (PURL) を構築
 * @param {string} name - パッケージ名
 * @param {string} version - バージョン
 * @param {string} ecosystem - エコシステム名（デフォルト: 'generic'）
 * @returns {string|undefined} PURL文字列、またはパラメータが無い場合undefined
 */
function buildPurl(name, version, ecosystem = 'generic') {
  if (!name || !version) {
    return undefined;
  }

  return `pkg:${ecosystem}/${name}@${version}`;
}

/**
 * UUID v4を生成
 * @returns {string} UUID v4文字列
 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replaceAll(/[xy]/g, (char) => {
    const random = Math.trunc(Math.random() * 16);
    const value = char === 'x' ? random : (random & 0x3) | 0x8;
    return value.toString(16);
  });
}

/**
 * 空の正規化SBOM構造を作成
 * @param {string} repoPath - リポジトリパス
 * @param {Object} metadata - メタデータ
 * @returns {Object} 空の正規化SBOM
 */
function createEmptyNormalizedSbom(repoPath, metadata = {}) {
  return {
    version: '1.1',
    format: 'normalized',
    components: [],
    dependencies: [],
    metadata: {
      timestamp: new Date().toISOString(),
      projectName: path.basename(repoPath),
      projectVersion: 'unknown',
      toolName: 'SBOM Vulnerability Scanner',
      toolVersion: '1.1',
      ...metadata,
    },
  };
}

/**
 * 依存関係マップを作成
 * @param {Array<Object>} entries - 依存関係エントリ
 * @returns {Map} 依存関係マップ
 */
function createDependencyMap(entries) {
  const dependencyMap = new Map();
  for (const entry of entries) {
    if (!entry?.ref) continue;
    dependencyMap.set(entry.ref, Array.isArray(entry.dependsOn) ? entry.dependsOn : []);
  }
  return dependencyMap;
}

/**
 * package.json マニフェストからSBOMを生成
 * @param {string} repoPath - リポジトリパス
 * @returns {Object} 正規化SBOM
 */
function generateManifestSbom(repoPath) {
  const sbom = createEmptyNormalizedSbom(repoPath, {
    sbomGenerator: 'manifest',
    generatorVersion: 'builtin',
    sourceFormat: 'manifest',
  });
  const packageJsonPath = path.join(repoPath, 'package.json');
  let packageJson = {};

  try {
    const content = fs.readFileSync(packageJsonPath, 'utf-8');
    packageJson = JSON.parse(content);
  } catch {
    return sbom;
  }

  sbom.metadata.projectName = packageJson.name || path.basename(repoPath);
  sbom.metadata.projectVersion = packageJson.version || 'unknown';

  const allDeps = {
    ...(packageJson.dependencies ?? {}),
    ...(packageJson.devDependencies ?? {}),
    ...(packageJson.optionalDependencies ?? {}),
  };

  for (const [name, version] of Object.entries(allDeps)) {
    const normalizedVersion = normalizeVersion(version);
    const isDev = Boolean(packageJson.devDependencies?.[name] !== undefined);
    sbom.components.push({
      id: `${name}@${normalizedVersion}`,
      name,
      version: normalizedVersion,
      type: 'library',
      purl: buildPurl(name, normalizedVersion, 'npm'),
      scope: isDev ? 'excluded' : 'required',
      isDev,
      isDirect: true,
      isTransitive: false,
      licenses: [],
      ecosystem: 'npm',
      locations: [],
    });
  }

  const lockFilePath = path.join(repoPath, 'package-lock.json');
  const dependencyMap = new Map();
  try {
    const lockContent = fs.readFileSync(lockFilePath, 'utf-8');
    const lockJson = JSON.parse(lockContent);

    if (lockJson.packages) {
      for (const [depPath, depInfo] of Object.entries(lockJson.packages)) {
        if (depPath === '' || !depInfo?.name || !depInfo?.version) continue;
        const ref = `${depInfo.name}@${depInfo.version}`;

        if (!sbom.components.some((component) => component.id === ref)) {
          sbom.components.push({
            id: ref,
            name: depInfo.name,
            version: depInfo.version,
            type: 'library',
            purl: buildPurl(depInfo.name, depInfo.version, 'npm'),
            scope: 'required',
            isDev: false,
            isDirect: false,
            isTransitive: true,
            licenses: [],
            ecosystem: 'npm',
            locations: [],
          });
        }

        if (depInfo.requires && typeof depInfo.requires === 'object') {
          dependencyMap.set(
            ref,
            Object.entries(depInfo.requires).map(([depName, depVersion]) => `${depName}@${normalizeVersion(depVersion)}`)
          );
        }
      }
    }
  } catch {
  }

  const rootDependsOn = sbom.components.filter((component) => component.isDirect).map((component) => component.id);
  sbom.dependencies.push({
    ref: `${sbom.metadata.projectName}@${sbom.metadata.projectVersion}`,
    dependsOn: rootDependsOn,
  });

  for (const [ref, dependsOn] of dependencyMap.entries()) {
    sbom.dependencies.push({ ref, dependsOn });
  }

  sbom.components.sort((left, right) => left.name.localeCompare(right.name));
  return sbom;
}

/**
 * CycloneDX ライセンス情報を収集
 * @param {Array} licenses - ライセンス配列
 * @returns {Array<string>} ライセンス文字列の配列
 */
function collectCycloneDxLicenses(licenses) {
  if (!Array.isArray(licenses)) {
    return [];
  }

  return licenses
    .map((entry) => {
      if (!entry || typeof entry !== 'object') return undefined;
      if (entry.expression) return entry.expression;
      if (entry.license && typeof entry.license === 'object') {
        return entry.license.id || entry.license.name || entry.license.url;
      }
      return undefined;
    })
    .filter(Boolean);
}

/**
 * CycloneDX SBOMを正規化
 * @param {Object} document - CycloneDXドキュメント
 * @param {string} repoPath - リポジトリパス
 * @param {Object} metadata - メタデータ
 * @returns {Object} 正規化SBOM
 */
function normalizeCycloneDxSbom(document, repoPath, metadata = {}) {
  const rootComponent = document && document.metadata && document.metadata.component ? document.metadata.component : undefined;
  const normalized = createEmptyNormalizedSbom(repoPath, {
    projectName: rootComponent && rootComponent.name ? rootComponent.name : path.basename(repoPath),
    projectVersion: rootComponent && rootComponent.version ? rootComponent.version : 'unknown',
    sourceFormat: 'cyclonedx-json',
    ...metadata,
  });

  const dependencies = Array.isArray(document && document.dependencies) ? document.dependencies : [];
  normalized.dependencies = dependencies.map((entry) => ({
    ref: entry.ref,
    dependsOn: Array.isArray(entry.dependsOn) ? entry.dependsOn : [],
  }));

  const dependencyMap = createDependencyMap(normalized.dependencies);
  const rootRef = rootComponent ? rootComponent['bom-ref'] || rootComponent.purl : undefined;
  const directRefs = new Set(rootRef && dependencyMap.has(rootRef) ? dependencyMap.get(rootRef) : []);
  const dependentRefs = new Set();
  for (const values of dependencyMap.values()) {
    for (const value of values) {
      dependentRefs.add(value);
    }
  }

  const components = Array.isArray(document && document.components) ? document.components : [];
  normalized.components = components
    .map((component) => {
      const ref = component['bom-ref'] || component.purl || `${component.name || 'component'}@${component.version || 'unknown'}`;
      return {
        id: ref,
        name: component.name || 'unknown',
        version: component.version || 'unknown',
        type: component.type || 'library',
        purl: component.purl,
        scope: component.scope || 'required',
        isDev: component.scope === 'excluded',
        isDirect: directRefs.has(ref),
        isTransitive: dependentRefs.has(ref) && !directRefs.has(ref),
        licenses: collectCycloneDxLicenses(component.licenses),
        ecosystem: component.purl ? String(component.purl).replace(/^pkg:/, '').split('/')[0] : undefined,
        locations: [],
      };
    })
    .sort((left, right) => left.name.localeCompare(right.name));

  return normalized;
}

/**
 * SPDXライセンス情報を収集
 * @param {Object} pkg - パッケージ情報
 * @returns {Array<string>} ライセンス文字列の配列
 */
function collectSpdxLicenses(pkg) {
  const licenses = [];
  if (pkg.licenseConcluded && pkg.licenseConcluded !== 'NOASSERTION') {
    licenses.push(pkg.licenseConcluded);
  }
  if (pkg.licenseDeclared && pkg.licenseDeclared !== 'NOASSERTION') {
    licenses.push(pkg.licenseDeclared);
  }
  return Array.from(new Set(licenses));
}

/**
 * SPDX PURLを見つける
 * @param {Object} pkg - パッケージ情報
 * @returns {string|undefined} PURL文字列またはundefined
 */
function findSpdxPurl(pkg) {
  if (!Array.isArray(pkg.externalRefs)) {
    return undefined;
  }

  const match = pkg.externalRefs.find((entry) =>
    entry && typeof entry.referenceType === 'string' && entry.referenceType.toLowerCase().includes('purl')
  );
  return match ? match.referenceLocator : undefined;
}

/**
 * SPDX SBOMを正規化
 * @param {Object} document - SPDXドキュメント
 * @param {string} repoPath - リポジトリパス
 * @param {Object} metadata - メタデータ
 * @returns {Object} 正規化SBOM
 */
function normalizeSpdxSbom(document, repoPath, metadata = {}) {
  const packages = Array.isArray(document && document.packages) ? document.packages : [];
  const relationships = Array.isArray(document && document.relationships) ? document.relationships : [];
  const packageById = new Map();
  for (const pkg of packages) {
    if (pkg && pkg.SPDXID) {
      packageById.set(pkg.SPDXID, pkg);
    }
  }

  const describedRefs = new Set(
    relationships
      .filter((entry) => entry && entry.spdxElementId === 'SPDXRef-DOCUMENT' && entry.relationshipType === 'DESCRIBES')
      .map((entry) => entry.relatedSpdxElement)
  );
  const dependsOnMap = new Map();
  for (const entry of relationships) {
    if (!entry || !entry.spdxElementId || !entry.relatedSpdxElement) continue;

    if (entry.relationshipType === 'DEPENDS_ON') {
      const list = dependsOnMap.get(entry.spdxElementId) || [];
      list.push(entry.relatedSpdxElement);
      dependsOnMap.set(entry.spdxElementId, list);
    } else if (entry.relationshipType === 'DEPENDENCY_OF') {
      const list = dependsOnMap.get(entry.relatedSpdxElement) || [];
      list.push(entry.spdxElementId);
      dependsOnMap.set(entry.relatedSpdxElement, list);
    }
  }

  const directRefs = new Set();
  for (const ref of describedRefs) {
    const values = dependsOnMap.get(ref) || [];
    for (const value of values) {
      directRefs.add(value);
    }
  }

  const transitiveRefs = new Set();
  for (const [sourceRef, values] of dependsOnMap.entries()) {
    if (describedRefs.has(sourceRef)) continue;
    for (const value of values) {
      transitiveRefs.add(value);
    }
  }

  const firstDescribedRef = describedRefs.values().next().value;
  const rootPackage = firstDescribedRef ? packageById.get(firstDescribedRef) : undefined;
  const normalized = createEmptyNormalizedSbom(repoPath, {
    projectName: rootPackage && rootPackage.name ? rootPackage.name : document.name || path.basename(repoPath),
    projectVersion: rootPackage && rootPackage.versionInfo ? rootPackage.versionInfo : 'unknown',
    sourceFormat: 'spdx-json',
    ...metadata,
  });

  normalized.dependencies = Array.from(dependsOnMap.entries()).map(([ref, dependsOn]) => ({ ref, dependsOn }));
  normalized.components = packages
    .filter((pkg) => pkg && pkg.SPDXID !== 'SPDXRef-DOCUMENT')
    .map((pkg) => {
      const purl = findSpdxPurl(pkg);
      return {
        id: pkg.SPDXID || `${pkg.name || 'package'}@${pkg.versionInfo || 'unknown'}`,
        name: pkg.name || 'unknown',
        version: pkg.versionInfo || 'unknown',
        type: pkg.primaryPackagePurpose ? String(pkg.primaryPackagePurpose).toLowerCase() : 'library',
        purl,
        scope: directRefs.has(pkg.SPDXID) || describedRefs.has(pkg.SPDXID) ? 'required' : 'indirect',
        isDev: false,
        isDirect: directRefs.has(pkg.SPDXID),
        isTransitive: transitiveRefs.has(pkg.SPDXID) && !directRefs.has(pkg.SPDXID),
        licenses: collectSpdxLicenses(pkg),
        ecosystem: purl ? String(purl).replace(/^pkg:/, '').split('/')[0] : undefined,
        locations: [],
      };
    })
    .sort((left, right) => left.name.localeCompare(right.name));

  return normalized;
}

module.exports = {
  normalizeVersion,
  buildPurl,
  generateUUID,
  createEmptyNormalizedSbom,
  createDependencyMap,
  generateManifestSbom,
  collectCycloneDxLicenses,
  normalizeCycloneDxSbom,
  collectSpdxLicenses,
  findSpdxPurl,
  normalizeSpdxSbom,
};
