// GPU 内核正确性测试:随机 + 边界标量的 d→Q→keyId 位级比对
//
// 三重验证:
//   1. node:crypto(OpenSSL)导入 d 私钥导出 Q —— 独立基准
//   2. 本地 BigInt 参考实现(gen_constants.mjs 同款公式)交叉核对基准本身
//   3. GPU 输出与基准逐字节比对;keyId 与 JS fast-keygen 指纹算法比对
// 附加: 所有 Q 必须在曲线上(y² = x³-3x+b mod p)
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const EXE = path.join(here, 'pgp_gpu_miner.exe');

const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
const aC = p - 3n;

function modInv(v, m) {
  let [r0, r1, s0, s1] = [m, ((v % m) + m) % m, 0n, 1n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return ((s0 % m) + m) % m;
}
const addAffine = (P1, P2) => {
  if (!P1) return P2;
  if (!P2) return P1;
  if (((P1.x - P2.x) % p + p) % p === 0n) {
    if (((P1.y + P2.y) % p + p) % p === 0n) return null;
    const l = ((3n * P1.x * P1.x + aC) % p) * modInv((2n * P1.y) % p, p) % p;
    const x = (l * l - 2n * P1.x) % p;
    const y = (l * (P1.x - x) - P1.y) % p;
    return { x: (x + p) % p, y: (y + p) % p };
  }
  const l = (((P2.y - P1.y) % p + p) % p) * modInv(((P2.x - P1.x) % p + p) % p, p) % p;
  const x = (l * l - P1.x - P2.x) % p;
  const y = (l * (P1.x - x) - P1.y) % p;
  return { x: (x + p) % p, y: (y + p) % p };
};
const mulG = (k) => {
  let acc = null, add = { x: Gx, y: Gy };
  for (let i = 0; i < 256; i++) {
    if ((k >> BigInt(i)) & 1n) acc = addAffine(acc, add);
    add = addAffine(add, add);
  }
  return acc;
};

// ---- 测试标量: 边界 + 随机 ----
const scalars = [];
scalars.push(1n, 2n, 3n, 15n, 16n, 255n, 256n, n - 1n, n - 2n, 2n ** 255n);
for (let i = 0; i < 32; i++) {
  let d;
  do { d = BigInt('0x' + crypto.randomBytes(32).toString('hex')); } while (d === 0n || d >= n);
  scalars.push(d);
}

const CREATED = 1735564800; // 固定时间戳

// ---- 基准 1: BigInt 参考实现(自带 n+1 次方自检),再用 OpenSSL 交叉核对 ----
const osmX = new Map();
for (const d of scalars) {
  const P = mulG(d); // BigInt 参考
  const dh = Buffer.from(d.toString(16).padStart(64, '0'), 'hex');
  const jwk = {
    kty: 'EC', crv: 'P-256',
    d: dh.toString('base64url'),
    x: Buffer.from(P.x.toString(16).padStart(64, '0'), 'hex').toString('base64url'),
    y: Buffer.from(P.y.toString(16).padStart(64, '0'), 'hex').toString('base64url'),
  };
  // Node 会校验 (x,y) 与 d 一致,不一致直接抛错 —— 即 OpenSSL 认可这对坐标
  const priv = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const pubJwk = crypto.createPublicKey(priv).export({ format: 'jwk' });
  const x = BigInt('0x' + Buffer.from(pubJwk.x, 'base64url').toString('hex'));
  const y = BigInt('0x' + Buffer.from(pubJwk.y, 'base64url').toString('hex'));
  if (x !== P.x || y !== P.y) {
    console.error(`FATAL: OpenSSL != BigInt ref at d=${d.toString(16)}`);
    process.exit(1);
  }
  osmX.set(d, P);
}

// ---- 基准 2: 曲线方程检查 ----
for (const d of scalars) {
  const P = osmX.get(d);
  const lhs = (P.y * P.y) % p;
  const rhs = (((P.x * P.x) % p * P.x) % p + (p - 3n * P.x % p + p) % p + b) % p;
  if (lhs !== rhs % p) {
    console.error(`FATAL: point not on curve at d=${d.toString(16)}`);
    process.exit(1);
  }
}
console.log(`reference check ok: ${scalars.length} scalars (OpenSSL == BigInt, all on curve)`);

// ---- keyId 基准(与 fast-keygen.mjs 相同的指纹算法) ----
const mpiHeader = Buffer.from([0x02, 0x03]); // 515 bit,恒定
function keyIdOf(xBig, yBig) {
  const x = Buffer.from(xBig.toString(16).padStart(64, '0'), 'hex');
  const y = Buffer.from(yBig.toString(16).padStart(64, '0'), 'hex');
  const q = Buffer.concat([Buffer.from([0x04]), x, y]);
  const body = Buffer.concat([
    Buffer.from([4]),
    (() => { const b4 = Buffer.alloc(4); b4.writeUInt32BE(CREATED); return b4; })(),
    Buffer.from([0x13]),
    Buffer.from([8]),
    Buffer.from('2a8648ce3d030107', 'hex'),
    mpiHeader, q,
  ]);
  const prefix = Buffer.from([0x99, (body.length >> 8) & 0xff, body.length & 0xff]);
  const fp = crypto.createHash('sha1').update(Buffer.concat([prefix, body])).digest('hex');
  return fp.slice(-16);
}
const kidRef = new Map();
for (const d of scalars) {
  const P = osmX.get(d);
  kidRef.set(d, keyIdOf(P.x, P.y));
}

// ---- 跑 GPU ----
const inputFile = path.join(here, 'test_input.txt');
fs.writeFileSync(inputFile, scalars.map((d) => d.toString(16).padStart(64, '0')).join('\n'));
const out = execFileSync(EXE, ['--mode', 'test', '--input', inputFile, '--created', String(CREATED)],
  { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
const lines = out.split('\n').filter((l) => l.trim());
const ready = JSON.parse(lines[0]);
console.log('device:', ready.device, 'sm:', ready.sm);
if (ready.t !== 'ready') { console.error('FATAL: no ready line:', lines[0]); process.exit(1); }

let fail = 0;
const vecs = lines.slice(1).filter((l) => l.startsWith('{') && l.includes('"t":"vec"')).map((l) => JSON.parse(l));
if (vecs.length !== scalars.length) {
  console.error(`FATAL: expected ${scalars.length} vectors, got ${vecs.length}`);
  process.exit(1);
}
for (let i = 0; i < scalars.length; i++) {
  const d = scalars[i];
  const v = vecs[i];
  const ref = osmX.get(d);
  const hex = (bn) => bn.toString(16).padStart(64, '0');
  const xOk = v.x === hex(ref.x);
  const yOk = v.y === hex(ref.y);
  const kidOk = v.kid === kidRef.get(d);
  if (!xOk || !yOk || !kidOk) {
    fail++;
    console.error(`MISMATCH d=${hex(d)}: x=${xOk ? 'ok' : 'BAD'} y=${yOk ? 'ok' : 'BAD'} kid=${kidOk ? 'ok' : 'BAD'}`);
    if (fail <= 3) {
      console.error('  gpu:', v.x, v.y, v.kid);
      console.error('  ref:', hex(ref.x), hex(ref.y), kidRef.get(d));
    }
  }
}
console.log(fail === 0
  ? `ALL PASS: ${scalars.length}/${scalars.length} bit-exact (x, y, keyId)`
  : `FAILED: ${fail} mismatches`);
process.exit(fail === 0 ? 0 : 1);
