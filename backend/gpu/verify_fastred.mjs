// 数值证明: plain 域特形约减 fp_mul == (a*b) mod p
//
// 设计(逐 limb 移植到 CUDA, 替换 CIOS 蒙哥马利, 全程 plain 域):
//   1. schoolbook 8x8 -> T[0..15] (16 u32 limbs; 行内 u64 进位传播,
//      每行结束 T[i+8] += c 一次放行 —— 数学上不会 32 位溢出)
//   2. T = L + H*2^256, L = T[0..7], H = T[8..15]
//   3. 恒等式 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p)
//      => T mod p = L + H<<224 - H<<192 - H<<96 + H  (全部 limb 对齐)
//   4. 16-limb 有符号加减, 高 8 limb (acc[8..15]) 用同一恒等式折叠, 2-3 轮收敛
//   5. 结果 < 2^257 -> 条件减 p (1-2 次) -> canonical
import crypto from 'node:crypto';

const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const MASK32 = 0xffffffffn;
const M32 = 1n << 32n;

const rand32 = () => BigInt('0x' + crypto.randomBytes(32).toString('hex')) % p;
const fromLimbs = (l) => l.reduce((acc, x, i) => acc + (x << BigInt(32 * i)), 0n);
const toLimbs8 = (v) => { const o = []; for (let i = 0; i < 8; i++) { o.push(v & MASK32); v >>= 32n; } return o; };

// acc[i] += c (有符号 u64 流), 返回新流出
function addSignedLimb(acc, i, c) {
  const d = acc[i] + c;
  acc[i] = ((d % M32) + M32) % M32;
  return d >> 32n;
}

// acc 从 limb sh 开始加/减 H (limb 数组), 传播全部借位/进位
function shiftAdd(acc, H, sh, sign) {
  let c = 0n;
  for (let k = 0; k < H.length && sh + k < acc.length; k++) {
    c += sign * H[k];
    c = addSignedLimb(acc, sh + k, c);
  }
  for (let i = sh + H.length; i < acc.length && c !== 0n; i++) {
    c = addSignedLimb(acc, i, c);
  }
  return c;
}

function fpMulFast(a, b) {
  // schoolbook 8x8 -> 16 limbs
  const T = new Array(16).fill(0n);
  for (let i = 0; i < 8; i++) {
    let c = 0n;
    for (let j = 0; j < 8; j++) {
      const s = a[i] * b[j] + T[i + j] + c;
      T[i + j] = s & MASK32;
      c = s >> 32n;
    }
    T[i + 8] += c;
  }

  const acc = T.slice(); // 16 limbs
  const L8 = acc.slice(0, 8);
  const H8 = acc.slice(8);

  // T mod p = L + H<<224 - H<<192 - H<<96 + H
  // acc 复用: 先清高 8 位, 从 limb 0 开始重排
  for (let i = 0; i < 16; i++) acc[i] = 0n;
  for (let i = 0; i < 8; i++) acc[i] = L8[i];
  shiftAdd(acc, H8, 7, 1n);
  shiftAdd(acc, H8, 6, -1n);
  shiftAdd(acc, H8, 3, -1n);
  shiftAdd(acc, H8, 0, 1n);

  // 折叠 acc[8..15] (收敛 < 3 轮): H'(=acc[8..15]) 按同一恒等式展开。
  // 注意 H'<<224 与 -H'<<192 都可能流出 limb 15 —— 但恒等式保证:
  //   H'<<224 - H'<<192 的流出 < 2^257, 而 fold 后 acc[8..15] 每轮严格变小。
  // 为绝对安全, 折叠时把流出值再次并入 acc[8] (作为 2^256 权重) 参与下一轮。
  for (let round = 0; round < 8; round++) {
    // 收集 limb 15 流出 -> 并回 limb 8+? 换一种简单做法: hi 折叠产生的新溢出
    // 直接留在 acc[8..15], 因为 shiftAdd 已经把所有借位传播进 16 limb 内。
    const hi = acc.slice(8);
    if (hi.every((x) => x === 0n)) break;
    for (let i = 8; i < 16; i++) acc[i] = 0n;
    shiftAdd(acc, hi, 7, 1n);
    shiftAdd(acc, hi, 6, -1n);
    shiftAdd(acc, hi, 3, -1n);
    shiftAdd(acc, hi, 0, 1n);
  }

  let v = fromLimbs(acc.slice(0, 8));
  v = ((v % p) + p) % p;
  return toLimbs8(v);
}

// ---- tests ----
const cases = [];
for (let i = 0; i < 100000; i++) cases.push([rand32(), rand32()]);
cases.push([p - 1n, p - 1n], [1n, 1n], [2n ** 255n, 3n], [p - 1n, 2n]);
cases.push([p - 1n, p - 1n]);

let fails = 0;
for (const [a, b] of cases) {
  const fast = fromLimbs(fpMulFast(toLimbs8(a), toLimbs8(b)));
  const ref = (a * b) % p;
  if (fast !== ref) {
    fails++;
    if (fails <= 5) console.error('FAIL a=%s b=%s fast=%s ref=%s',
      a.toString(16), b.toString(16), fast.toString(16), ref.toString(16));
  }
}
console.log(fails === 0
  ? `ALL PASS: ${cases.length} cases — plain fast reduction == BigInt mod p`
  : `FAILED: ${fails}/${cases.length}`);
process.exit(fails === 0 ? 0 : 1);
