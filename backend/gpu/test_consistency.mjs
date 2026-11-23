// 终极裁决: mulG(d) vs 命中 x/y —— GPU 挖矿管线的 (d,x,y) 是否真正一致
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const exe = path.join(process.cwd(), 'gpu', 'pgp_gpu_miner.exe');
const rulesPath = path.join(process.cwd(), 'gpu', 'tmp_rules.txt');
fs.writeFileSync(rulesPath, 'consecutive 5\n');
const out = execFileSync(exe, ['--batch', '262144', '--duration', '6', '--created', String(Math.floor(Date.now() / 1000)), '--rules', rulesPath], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, input: 'x\n' });
fs.unlinkSync(rulesPath);
const hit = JSON.parse(out.split('\n').find((l) => l.includes('"t":"hit"')));

const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const aC = p - 3n;
const Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
function modInv(v, m) { let [r0, r1, s0, s1] = [m, v % m, 0n, 1n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return ((s0 % m) + m) % m; }
const addAff = (P1, P2) => {
  if (!P1) return P2;
  if (!P2) return P1;
  if (((P1.x - P2.x) % p + p) % p === 0n) {
    if (((P1.y + P2.y) % p + p) % p === 0n) return null;
    const l = ((3n * P1.x * P1.x + aC) % p) * modInv((2n * P1.y) % p, p) % p;
    const x = (l * l - 2n * P1.x) % p;
    return { x: (x + p) % p, y: ((l * (P1.x - x) - P1.y) % p + p) % p };
  }
  const l = (((P2.y - P1.y) % p + p) % p) * modInv(((P2.x - P1.x) % p + p) % p, p) % p;
  const x = (l * l - P1.x - P2.x) % p;
  return { x: (x + p) % p, y: ((l * (P1.x - x) - P1.y) % p + p) % p };
};
const mulG = (k) => {
  let acc = null, add = { x: Gx, y: Gy };
  for (let i = 0; i < 256; i++) { if ((k >> BigInt(i)) & 1n) acc = addAff(acc, add); add = addAff(add, add); }
  return acc;
};

const d = BigInt('0x' + hit.d);
const Q = mulG(d);
const gx = Q.x.toString(16).padStart(64, '0');
const gy = Q.y.toString(16).padStart(64, '0');
console.log('hit x :', hit.x);
console.log('mulG x:', gx);
console.log('hit y :', hit.y);
console.log('mulG y:', gy);
console.log('VERDICT:', (gx === hit.x && gy === hit.y) ? 'CONSISTENT — GPU 管线正确,问题在 WebCrypto 校验' : 'INCONSISTENT — GPU 挖矿管线给出的 (d,x,y) 不匹配!');

// 同时检验: createPrivateKey 到底是否校验一致性(用人为不一致的三元组)
const b64u = (hex) => Buffer.from(hex, 'hex').toString('base64url');
try {
  crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: b64u(hit.d), x: b64u(gx.slice(0, 62) + '00'), y: b64u(gy) }, format: 'jwk' });
  console.log('createPrivateKey 对篡改 x(末字节改 00): 接受 —— 它不校验一致性!');
} catch {
  console.log('createPrivateKey 对篡改 x(末字节改 00): 拒绝');
}
