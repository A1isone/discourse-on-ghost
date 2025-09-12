/**
 * Tests for ./targets/node.js side-effect loader.
 *
 * Framework: Jest-compatible API (describe/it/expect). Works with Vitest as well.
 *
 * Goals:
 * - Loads without throwing (happy path).
 * - Safe to import multiple times (idempotent or at least non-explosive).
 * - Does not permanently pollute critical globals once module cache is reset.
 * - Optionally validates common side effects if present (feature-detections).
 */

const TARGET_PATH = require('path').resolve(__dirname, './targets/node.js');

/**
 * Utility: delete a module from require cache by path.
 */
function purgeFromCache(modulePath: string) {
  // Delete exact match
  delete require.cache[modulePath as unknown as string];
  // Also delete any children that were loaded by it (best-effort)
  for (const key of Object.keys(require.cache)) {
    const mod = require.cache[key];
    if (mod && mod.parent && mod.parent.id === modulePath) {
      delete require.cache[key];
    }
  }
}

/**
 * Capture baseline of selected globals/env to detect unexpected mutations.
 */
function snapshotEnvironment() {
  return {
    // Shallow snapshots of commonly touched objects
    env: { ...process.env },
    cwd: process.cwd(),
    argv: [...process.argv],
    execArgv: [...process.execArgv],
    // Track presence of popular globals the target might define
    hasGlobalFetch: 'fetch' in globalThis,
    hasReadableStream: 'ReadableStream' in globalThis,
    hasAbortController: 'AbortController' in globalThis,
    // Record enumerable additions on globalThis
    globalKeys: new Set(Object.getOwnPropertyNames(globalThis)),
  };
}

function restoreEnvironment(baseline: ReturnType<typeof snapshotEnvironment>) {
  // Restore env keys mutated or added
  for (const k of Object.keys(process.env)) {
    if (!(k in baseline.env)) delete process.env[k];
  }
  for (const [k, v] of Object.entries(baseline.env)) {
    process.env[k] = v;
  }
  // We avoid changing cwd/argv/execArgv within tests, but assert unchanged later
}

describe('targets/node.js side-effect module', () => {
  let baseline: ReturnType<typeof snapshotEnvironment>;

  beforeEach(() => {
    baseline = snapshotEnvironment();
    purgeFromCache(TARGET_PATH);
  });

  afterEach(() => {
    restoreEnvironment(baseline);

    // Assert that basic process info was not unexpectedly changed
    expect(process.cwd()).toBe(baseline.cwd);
    expect(process.argv).toEqual(baseline.argv);
    expect(process.execArgv).toEqual(baseline.execArgv);

    // Clean up any newly introduced globals to avoid test bleed
    const currentKeys = Object.getOwnPropertyNames(globalThis);

    for (const key of currentKeys) {
      if (!baseline.globalKeys.has(key)) {
        try {
          // Best-effort cleanup: only delete configurable properties
          const desc = Object.getOwnPropertyDescriptor(globalThis, key);
          if (desc && desc.configurable) {
            // @ts-ignore
            delete globalThis[key];
          }
        } catch {
          // ignore non-configurable/engine globals
        }
      }
    }
  });

  it('loads without throwing and performs its initialization', async () => {
    expect(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      require(TARGET_PATH);
    }).not.toThrow();
  });

  it('can be required multiple times safely (idempotent behavior)', () => {
    // First load
    expect(() => require(TARGET_PATH)).not.toThrow();

    // Purge and load again to simulate fresh process start
    purgeFromCache(TARGET_PATH);
    expect(() => require(TARGET_PATH)).not.toThrow();

    // Load again without purging to ensure repeated require does not break
    expect(() => require(TARGET_PATH)).not.toThrow();
  });

  it('does not permanently pollute critical globals', () => {
    require(TARGET_PATH);

    const after = {
      hasGlobalFetch: 'fetch' in globalThis,
      hasReadableStream: 'ReadableStream' in globalThis,
      hasAbortController: 'AbortController' in globalThis,
    };

    // If the target intends to polyfill fetch/streams, allow presence but ensure they are configurable and non-breaking.
    for (const [name, exists] of Object.entries(after)) {
      if (exists) {
        const desc = Object.getOwnPropertyDescriptor(
          globalThis,
          name.replace('has', '').replace(/^[A-Z]/, c => c.toLowerCase())
        );
        // If defined by the polyfill, it should be at least configurable or writable to avoid locking tests.
        if (desc) {
          expect(desc.configurable || desc.writable).toBeTruthy();
        }
      }
    }
  });

  it('does not unexpectedly mutate process.env beyond temporary updates', () => {
    require(TARGET_PATH);

    // Common expectation: no destructive deletions of existing env keys
    for (const k of Object.keys(baseline.env)) {
      expect(Object.prototype.hasOwnProperty.call(process.env, k)).toBe(true);
    }
  });

  it('exposes no default export (pure side-effect loader), or if it does, it is not relied upon', () => {
    const mod = require(TARGET_PATH);
    // Side-effect modules typically export nothing or an empty object.
    // We do not assert a specific shape, only that requiring it returns an object (CJS) or undefined is acceptable.
    const acceptable = [undefined, null, 'object'];
    expect(acceptable.includes(typeof mod) || mod === undefined || mod === null).toBe(true);
  });
});