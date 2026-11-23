// GPU(CUDA)挖掘 Worker
//
// 架构: 本 worker 拉起 gpu/pgp_gpu_miner.exe(GPU 做标量乘+SHA-1,主机预筛),
//        对每条 hit 做零信任复验后走与 CPU worker 完全相同的 completeKey 路径。
//
// 验证链(不信任 GPU 输出的任何单字段):
//   1. createPrivateKey(JWK d+x+y) —— Node 校验 (x,y) 与 d 一致(在曲线上),不一致直接抛错
//   2. 用 x,y+created 重建公钥包体重算 SHA-1,keyId 必须与 GPU 报告一致
//   3. matchRules(keyId, ...) —— 与 CPU 相同的真实规则引擎复验
//   4. completeKey(OpenPGP 组装) 与 CPU worker 字节级一致(复用 fast-keygen 导出函数)
//
// 规则不受支持(如无必需字面量的正则)时发 gpu_unsupported,由 task-manager 回落 CPU。
import { parentPort, workerData } from 'node:worker_threads';
import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import * as openpgp from 'openpgp';
import {
  matchRules,
  packet,
  buildPublicKeyBody,
  buildSecretKeyBody,
  computeFingerprint,
  extractKeyId,
} from '../lib/pgp/fast-keygen.mjs';

const { patterns, logicOperator, groups } = workerData;
const exePath = path.join(process.cwd(), 'gpu', 'pgp_gpu_miner.exe');
const rulesPath = path.join(process.cwd(), 'data', `gpu-rules-${Date.now()}.txt`);

// ---------- 规则文件 ----------
function ruleLines() {
  const lines = [];
  const push = (r) => {
    if (!r || !r.enabled) return;
    const p = r.params || {};
    const s = (t, v) => `${t} ${v}`;
    switch (r.type) {
      case 'consecutive':   lines.push(s('consecutive', p.minLength || 5)); break;
      case 'repeating':     lines.push(s('repeating', p.minLength || 3)); break;
      case 'palindrome':    lines.push(s('palindrome', p.minLength || 5)); break;
      case 'leading_zeros': lines.push(s('leading_zeros', p.zeroCount || 5)); break;
      case 'special_date':
        if (p.pattern) {
          if (/[\r\n]/.test(p.pattern)) lines.push('UNSUPPORTED special_date with newline');
          else lines.push(s('special_date', p.pattern));
        }
        break;
      case 'custom_regex':
        if (p.pattern) {
          if (/[\r\n]/.test(p.pattern)) lines.push('UNSUPPORTED regex with newline');
          else lines.push(s('custom_regex', p.pattern));
        }
        break;
    }
  };
  patterns.forEach(push);
  (groups || []).forEach((g) => { if (g.enabled) (g.rules || []).forEach(push); });
  return lines;
}

const lines = ruleLines();
if (lines.length === 0) {
  parentPort.postMessage({ type: 'gpu_unsupported', message: 'no enabled rules for GPU engine' });
  process.exit(0);
}
if (lines.some((l) => l.startsWith('UNSUPPORTED'))) {
  parentPort.postMessage({ type: 'gpu_unsupported', message: lines.find((l) => l.startsWith('UNSUPPORTED')) });
  process.exit(0);
}
fs.mkdirSync(path.dirname(rulesPath), { recursive: true });
fs.writeFileSync(rulesPath, lines.join('\n') + '\n');

// ---------- 跑 exe ----------
const created = Math.floor(Date.now() / 1000); // 整个 GPU 会话用同一时间戳
// batch: 1M/批,GTX 1650 实测最优(比 256K 高约 9%;GPU 侧规则预筛后每批只回传命中)
const args = ['--batch', String(1 << 20), '--created', String(created), '--rules', rulesPath];

let child;
try {
  child = spawn(exePath, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
} catch (e) {
  parentPort.postMessage({ type: 'gpu_unsupported', message: 'gpu exe not found: ' + e.message });
  process.exit(0);
}

parentPort.on('message', (msg) => {
  if (msg && msg.type === 'stop') {
    try { child.stdin.end(); child.kill(); } catch { /* 已退出 */ }
  }
});

let stderrTail = '';
child.stderr.on('data', (d) => {
  stderrTail = (stderrTail + d.toString()).slice(-2000);
});
child.on('exit', (code) => {
  fs.unlink(rulesPath, () => {});
  if (code === 2) {
    // 规则不受支持(由 exe 报告)
    parentPort.postMessage({ type: 'gpu_unsupported', message: stderrTail || 'unsupported rules' });
    process.exit(0);
  }
  if (code !== 0 && code !== null) {
    parentPort.postMessage({ type: 'error', message: `gpu miner exited code=${code}: ${stderrTail.slice(-300)}` });
  }
  parentPort.postMessage({ type: 'stopped' });
  process.exit(0);
});

// ---------- 命中处理 ----------
let attempts = 0;
let matchCount = 0;
let lastTotal = 0;
let lastMatches = 0;
let matchBroadcastCount = 0;
const MATCH_BROADCAST_INTERVAL = 25;

async function completeKey(secretKeyBinary) {
  const priv = await openpgp.readPrivateKey({ binaryKey: secretKeyBinary });
  const fmt = await openpgp.reformatKey({
    privateKey: priv,
    userIDs: [{ name: 'PGP Vanity Miner', email: 'miner@localhost' }],
    passphrase: '',
    format: 'armored',
  });
  let key = await openpgp.readPrivateKey({ armoredKey: fmt.privateKey });
  key = await key.addSubkey({});
  const publicKey = key.toPublic().armor();
  const privateKey = key.armor();
  const pub = await openpgp.readKey({ armoredKey: publicKey });
  return {
    publicKey,
    privateKey,
    fingerprint: pub.getFingerprint(),
    keyId: pub.getKeyID().toHex(),
  };
}

const b64u = (hex) => Buffer.from(hex, 'hex').toString('base64url');

function validateAndRebuild(hit) {
  // 1. JWK 一致性(Node 原生校验 (x,y) 与 d 匹配、点在曲线上)
  crypto.createPrivateKey({
    key: { kty: 'EC', crv: 'P-256', d: b64u(hit.d), x: b64u(hit.x), y: b64u(hit.y) },
    format: 'jwk',
  });

  // 2. 重算指纹: 与 fast-keygen.mjs 字节级同一套组包代码
  const x = Buffer.from(hit.x, 'hex');
  const y = Buffer.from(hit.y, 'hex');
  const d = Buffer.from(hit.d, 'hex');
  const createdBuf = Buffer.alloc(4);
  createdBuf.writeUInt32BE(hit.created, 0);
  const q = Buffer.concat([Buffer.from([0x04]), x, y]);
  const publicKeyBody = buildPublicKeyBody(createdBuf, q);
  const fingerprint = computeFingerprint(publicKeyBody);
  const keyId = extractKeyId(fingerprint);
  if (keyId !== hit.kid) throw new Error(`keyId mismatch: gpu=${hit.kid} recomputed=${keyId}`);

  // 3. 真实规则引擎复验
  const result = matchRules(keyId, patterns, groups || [], logicOperator || 'OR');
  if (!result.matched || result.hits.length === 0) throw new Error('rule revalidation failed');

  // 4. 完整 OpenPGP 密钥材料(与搜索阶段同一份 created/q/d)
  const secretKeyBinary = packet(5, buildSecretKeyBody(createdBuf, q, d));
  return { secretKeyBinary, fingerprint, keyId, result };
}

// JSON 行解析缓冲
let buf = '';
child.stdout.on('data', (chunk) => {
  buf += chunk.toString('utf8');
  let idx;
  while ((idx = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    handleLine(line);
  }
});

function handleLine(line) {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }

  switch (msg.t) {
    case 'ready':
      console.log(`[GpuWorker] GPU 就绪: ${msg.device} sm_${msg.sm} batch=${msg.batch}`);
      break;
    case 'prog': {
      const delta = msg.total - lastTotal;
      lastTotal = msg.total;
      attempts += delta;
      // 注意: matchesDelta 不在这里报——exe 侧 hits 是预筛命中(含假阳性),
      // 真实匹配数由定时器按 matchCount(completeKey 成功数)汇报
      parentPort.postMessage({
        type: 'progress',
        attempts: delta,
        hashrate: msg.rate,
        totalAttempts: attempts,
        matchesDelta: 0,
      });
      break;
    }
    case 'hit': {
      // 命中复验 + 组装(异步,不阻塞读管道——openpgp 组装较慢,靠流控自然排队)
      handleHit(msg);
      break;
    }
    case 'warn':
      console.warn('[GpuWorker]', msg.message);
      break;
    case 'error':
      console.error('[GpuWorker]', msg.message);
      parentPort.postMessage({ type: 'error', message: msg.message });
      break;
    case 'done':
      break;
  }
}

const hitQueue = [];
let draining = false;

async function drainQueue() {
  if (draining) return;
  draining = true;
  try {
    while (hitQueue.length > 0) {
      const item = hitQueue.shift();
      try {
        const full = await completeKey(item.secretKeyBinary);
        matchCount++;
        matchBroadcastCount++;
        parentPort.postMessage({
          type: 'match',
          broadcast: matchBroadcastCount % MATCH_BROADCAST_INTERVAL === 0,
          publicKey: full.publicKey,
          privateKey: full.privateKey,
          fingerprint: full.fingerprint,
          keyId: full.keyId,
          patternId: item.patternId,
          patternType: item.patternType,
          color: item.color,
          matchPosition: item.position,
          matchedText: item.matchedText,
          attempts: item.attempts,
        });
      } catch (e) {
        parentPort.postMessage({ type: 'error', message: String(e && e.message || e) });
      }
    }
  } finally {
    draining = false;
  }
}

function handleHit(hit) {
  // 计数不在这里做: matchCount 在 drainQueue(completeKey 成功后)与 CPU worker 语义一致
  try {
    const v = validateAndRebuild(hit);
    const best = v.result.hits.slice().sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];
    hitQueue.push({
      secretKeyBinary: v.secretKeyBinary,
      patternId: best.ruleId,
      patternType: best.patternType,
      color: best.color,
      position: best.position,
      matchedText: best.matchedText,
      attempts: lastTotal || 1,
    });
    if (hitQueue.length > 200) hitQueue.shift();
    drainQueue();
  } catch (e) {
    console.error('[GpuWorker] 命中复验失败(已丢弃):', e && e.message);
    parentPort.postMessage({ type: 'error', message: 'gpu hit revalidation failed: ' + (e && e.message) });
  }
}

// 定期汇报 attempts(命中复验路径里 attempts 只在 prog 里累积,补充匹配数汇报)
setInterval(() => {
  if (matchCount !== lastMatches) {
    const mDelta = matchCount - lastMatches;
    lastMatches = matchCount;
    parentPort.postMessage({
      type: 'progress',
      attempts: 0,
      hashrate: 0,
      totalAttempts: attempts,
      matchesDelta: mDelta,
    });
  }
}, 1000).unref?.();
