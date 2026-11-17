/**
 * Branch-coverage tests for diagnostic-collector.ts.
 *
 * Targets the two previously uncovered paths:
 *   Line 37-38: fs.mkdirSync throws → logger.warn + early return
 *   Line 102:   sanitizeDockerComposeYaml throws → logger.debug swallows error
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
jest.mock('execa', () => require('./test-helpers/mock-execa.test-utils').execaMockFactory());

jest.mock('./compose-sanitizer', () => ({
  sanitizeDockerComposeYaml: jest.fn(),
}));

const mockMkdirSync = jest.fn();
jest.mock('fs', () => {
  const actual = jest.requireActual<typeof import('fs')>('fs');
  return {
    ...actual,
    mkdirSync: (...args: Parameters<typeof actual.mkdirSync>) => mockMkdirSync(...args),
  };
});

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { collectDiagnosticLogs } from './diagnostic-collector';
import { sanitizeDockerComposeYaml } from './compose-sanitizer';
import { mockExecaFn } from './test-helpers/mock-execa.test-utils';

const actual = jest.requireActual<typeof import('fs')>('fs');
const mockSanitize = sanitizeDockerComposeYaml as jest.MockedFunction<typeof sanitizeDockerComposeYaml>;

describe('collectDiagnosticLogs – uncovered branches', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = actual.mkdtempSync(path.join(os.tmpdir(), 'awf-diag-'));
    jest.clearAllMocks();
    mockExecaFn.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
    // Default: delegate to real mkdirSync
    mockMkdirSync.mockImplementation((...args: Parameters<typeof actual.mkdirSync>) =>
      actual.mkdirSync(...args)
    );
  });

  afterEach(() => {
    actual.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns early and warns when diagnostics directory cannot be created', async () => {
    mockMkdirSync.mockImplementationOnce(() => {
      throw new Error('EACCES: permission denied');
    });

    await expect(collectDiagnosticLogs(tmpDir)).resolves.toBeUndefined();
    // No docker calls should have been made after the early return
    expect(mockExecaFn).not.toHaveBeenCalled();
  });

  it('swallows sanitize errors when writing compose diagnostics fails', async () => {
    mockSanitize.mockImplementationOnce(() => {
      throw new Error('sanitize failure');
    });

    const composeFile = path.join(tmpDir, 'docker-compose.yml');
    actual.writeFileSync(composeFile, 'services: {}');

    await expect(collectDiagnosticLogs(tmpDir)).resolves.toBeUndefined();

    const diagnosticsDir = path.join(tmpDir, 'diagnostics');
    expect(fs.existsSync(path.join(diagnosticsDir, 'docker-compose.yml'))).toBe(false);
  });

  it('redacts credentials in captured container diagnostic logs', async () => {
    const secretToken = `ghs_${'z'.repeat(36)}`;
    const secretJwt = `eyJ${'a'.repeat(16)}.${'b'.repeat(16)}.${'c'.repeat(16)}-`;
    mockExecaFn.mockImplementation(async (_cmd: string, args: string[]) => {
      if (args[0] === 'logs') {
        return {
          stdout: `Authorization: Bearer ${secretToken}`,
          stderr: `token=${secretJwt}`,
          exitCode: 0,
        };
      }
      return { stdout: '', stderr: '', exitCode: 0 };
    });

    await collectDiagnosticLogs(tmpDir);

    const logContent = actual.readFileSync(path.join(tmpDir, 'diagnostics', 'awf-agent.log'), 'utf8');
    expect(logContent).not.toContain(secretToken);
    expect(logContent).not.toContain(secretJwt);
    expect(logContent).toContain('[REDACTED_CREDENTIAL]');
  });
});
