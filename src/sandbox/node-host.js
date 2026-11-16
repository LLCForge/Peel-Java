// Node (CLI ve testler) için bekçili sandbox: motor ayrı, yalıtılmış bir alt süreçte çalışır (node --permission; yalnızca
// src/ ve fflate okunabilir; yazma, ağ, alt süreç, worker kapalı). Kilitlenen ya da çöken süreç bekçi tarafından
// öldürülüp yeniden başlatılır.
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { sandboxApi } from './api.js';
import { createWatchdog } from './watchdog.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const src = path.resolve(here, '..');
const PROC = path.join(here, 'node-proc.js');
const fflateDir = () => realpathSync(path.dirname(path.dirname(createRequire(import.meta.url).resolve('fflate'))));

export function createNodeSandbox() {
  const allow = [realpathSync(src), fflateDir()];
  const dog = createWatchdog({
    spawn() {
      const child = fork(PROC, [], {
        execArgv: ['--permission', ...allow.map((d) => `--allow-fs-read=${d}${path.sep}*`), '--max-old-space-size=1024'],
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
        serialization: 'advanced',
      });
      let onErr = () => {};
      let stderr = '';
      child.stderr.on('data', (d) => { stderr = (stderr + d).slice(-2000); });
      child.on('error', (e) => onErr(e?.message ?? String(e)));
      child.on('exit', (code) => { if (code !== 0 && code !== null) onErr(`sandbox süreci çıktı (${code}): ${stderr.trim().split('\n').find((l) => /Error/.test(l)) ?? ''}`); });
      return {
        post: (m) => child.send(m),
        onMessage: (cb) => child.on('message', (m) => { if (!m?.ready) cb(m); }),
        onError: (cb) => { onErr = cb; },
        terminate: () => { onErr = () => {}; child.kill(); },
        ref: () => { child.ref(); child.channel?.ref(); },
        unref: () => { child.unref(); child.channel?.unref(); },
      };
    },
  });
  return { ...sandboxApi(dog.send), watchdogStats: dog.stats, kill: (reason) => dog.kill(reason), close: () => dog.terminate() };
}
