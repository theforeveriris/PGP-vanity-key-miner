// 生成 P-256 CUDA 内核所需的全部常数（v3: plain 域, 8x32bit 小端 limb）
// 运行: node gen_constants.mjs  > p256_constants.h
import crypto from 'node:crypto';

const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const a = p - 3n;
const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

const R = (1n << 256n) % p;          // R mod p (kept for reference/self-check only)
const R2 = (R * R) % p;

function toMont(v) { return (v * R) % p; }

function modInv(v, m) { // 扩展欧几里得：余数行驱动迭代，商从余数行取
  let [r0, r1, s0, s1] = [m, ((v % m) + m) % m, 0n, 1n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return ((s0 % m) + m) % m;
}

// ---- 仿射点加法（仅用于离线生成常数表,无穷点 = null）----
const addAffine = (P1, P2) => {
  if (!P1) return P2;
  if (!P2) return P1;
  if (((P1.x - P2.x) % p + p) % p === 0n) {
    if (((P1.y + P2.y) % p + p) % p === 0n) return null; // P1 = -P2
    // 倍点（j<=15 不会走到 y=0 的退化情形）
    const l = ((3n * P1.x * P1.x + a) % p) * modInv((2n * P1.y) % p, p) % p;
    const x = (l * l - 2n * P1.x) % p;
    const y = (l * (P1.x - x) - P1.y) % p;
    return { x: (x + p) % p, y: (y + p) % p };
  }
  const l = (((P2.y - P1.y) % p + p) % p) * modInv(((P2.x - P1.x) % p + p) % p, p) % p;
  const x = (l * l - P1.x - P2.x) % p;
  const y = (l * (P1.x - x) - P1.y) % p;
  return { x: (x + p) % p, y: (y + p) % p };
};

// 标量乘 k*G（普通 double-and-add,仅用于生成常数表）
const mulG = (k) => {
  let acc = null, add = { x: Gx, y: Gy };
  for (let i = 0; i < 256; i++) {
    if ((k >> BigInt(i)) & 1n) acc = addAffine(acc, add);
    add = addAffine(add, add);
  }
  return acc;
};

// ---- 自检：用 n 的倍数必须回到无穷点（验证表生成代码本身没写错）----
if (mulG(5n) === null || mulG(n + 1n)?.x !== Gx) {
  // (n+1)G = G
  console.error('FATAL: reference scalar-mult self-check failed');
  process.exit(1);
}
const t5 = mulG(5n);
const t2x3 = addAffine(mulG(2n), mulG(3n));
if (t5.x !== t2x3.x || t5.y !== t2x3.y) {
  console.error('FATAL: 5G != 2G+3G');
  process.exit(1);
}

const limbs = (v) => {
  const out = [];
  for (let i = 0; i < 8; i++) { out.push(v & 0xffffffffn); v >>= 32n; }
  return out.map((x) => '0x' + x.toString(16).padStart(8, '0') + 'u').join(', ');
};

const fmtArr = (name, values) =>
  `__constant__ u32 ${name}[${values.length * 8}] = {\n  ` +
  values.map(limbs).join(',\n  ') + '\n};\n';

const table = [];
for (let j = 1n; j <= 15n; j++) {
  const P = mulG(j);
  table.push({ x: toMont(P.x), y: toMont(P.y) });   // v4: Montgomery domain
}
const xs = table.map((t) => t.x);
const ys = table.map((t) => t.y);

const twoG = mulG(2n);
const montTwoGX = toMont(twoG.x);
const montTwoGY = toMont(twoG.y);


process.stdout.write(
  `// Auto-generated: node gen_constants.mjs -- do not hand-edit
// v4: Montgomery domain (CIOS with zero-multiply REDC row). Table points are
// plain affine values; P256_B is plain; MONT_ONE/R kept only for reference.
#pragma once
#include <cstdint>
using u32 = uint32_t;
using u64 = uint64_t;

#define P256_N0 0x1u   // legacy define (unused in v3 plain-domain kernel)

__constant__ u32 P256_P[8]   = { ${limbs(p)} };
__constant__ u32 P256_R2[8]  = { ${limbs(R2)} };      // reference only
__constant__ u32 P256_ONE[8] = { ${limbs(1n)} };      // plain 1
__constant__ u32 P256_MONT_ONE[8] = { ${limbs(R)} };  // reference only (legacy name)
__constant__ u32 P256_B[8]   = { ${limbs(toMont(b))} }; // curve b, Montgomery domain

__constant__ u32 P256_2GX[8] = { ${limbs(montTwoGX)} }; // affine 2G x, Montgomery domain
__constant__ u32 P256_2GY[8] = { ${limbs(montTwoGY)} }; // affine 2G y, Montgomery domain

` +
  fmtArr('P256_GX', xs) + '\n' +
  fmtArr('P256_GY', ys) + '\n' +
  `// check: R mod p = ${R.toString(16)} (reference only; kernel is plain-domain)\n`
);
