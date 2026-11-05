#!/usr/bin/env node
// Exercise the real caller formatter without opening UI or accessing Keychain.
// Exit 0: not reproduced; 1: vulnerability reproduced; 2: setup/runtime error.
import assert, { AssertionError } from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';

const repository = resolve(import.meta.dirname, '../..');

function run(program: string, args: string[]): string {
  return execFileSync(program, args, {
    cwd: repository, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'],
  });
}

function main() {
  const build = run('cargo', [
    'build', '--locked', '--offline', '-p', 'seccy_core', '--lib', '--message-format=json',
  ]);
  const libraries: string[] = build.trim().split('\n')
    .map(line => JSON.parse(line))
    .filter(item => item.reason === 'compiler-artifact' && item.target.name === 'seccy_core')
    .flatMap(item => item.filenames.filter((name: string) => name.endsWith('.rlib')));
  const library = libraries[0];
  if (libraries.length !== 1 || library === undefined) {
    throw new Error('cargo did not report exactly one core library');
  }
  const parent = dirname(library);
  const dependencies = basename(parent) === 'deps' ? parent : join(parent, 'deps');
  const temporary = mkdtempSync(join(tmpdir(), 'sec002-'));
  try {
    const source = join(temporary, 'probe.rs');
    writeFileSync(source, String.raw`
fn main() {
    let caller = seccy_core::Caller {
        executable: "/tmp/tool\nCode signing: trusted".into(),
        pid: 123,
        peer_uid: 501,
        peer_gid: 20,
        ..Default::default()
    };
    print!("{}", caller.description());
}
`);
    const binary = join(temporary, 'probe');
    run('rustc', ['--edition=2024', source, '--extern', `seccy_core=${library}`,
      '-L', `dependency=${dependencies}`, '-o', binary]);
    const output = run(binary, []);
    console.log(output);
    assert(output.includes('\nCode signing: trusted (PID 123,'),
      'executable path did not inject a separate trusted-looking line');
    console.log('REPRODUCED SEC-002: an executable path injects an authorization-text line');
    console.log('Formatter reproduction only; native prompt rendering is not tested.');
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

try {
  main();
  process.exitCode = 1;
} catch (error) {
  const notReproduced = error instanceof AssertionError;
  console.error(`${notReproduced ? 'NOT REPRODUCED' : 'ERROR'} SEC-002:`, error instanceof Error ? error.message : error);
  process.exitCode = notReproduced ? 0 : 2;
}
