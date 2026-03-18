const { exec, execSync } = require('node:child_process');
const { promisify } = require('node:util');

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

async function runCommand(command, options = {}) {
  return execAsync(command, {
    maxBuffer: 100 * 1024 * 1024,
    ...options,
  });
}

async function runSyftSbomCommand(repoPath, nativeFormat) {
  return runCommand(`syft "${repoPath}" -o ${nativeFormat}`);
}

async function runTrivySbomCommand(repoPath, nativeFormat) {
  return runCommand(`trivy fs --format ${nativeFormat} --quiet "${repoPath}"`);
}

async function runTrivyScanCommand(repoPath) {
  return runCommand(`trivy fs --format json --quiet "${repoPath}"`, {
    maxBuffer: 50 * 1024 * 1024,
  });
}

async function runNpmAuditCommand(targetPath) {
  return runCommand(`cd "${targetPath}" && npm audit --json --package-lock-only`);
}

async function prepareNpmPackageLock(targetPath) {
  return runCommand(`cd "${targetPath}" && npm install --package-lock-only --ignore-scripts --no-audit --fund=false`);
}

module.exports = {
  detectTrivyVersion,
  detectSyftVersion,
  runSyftSbomCommand,
  runTrivySbomCommand,
  runTrivyScanCommand,
  runNpmAuditCommand,
  prepareNpmPackageLock,
};