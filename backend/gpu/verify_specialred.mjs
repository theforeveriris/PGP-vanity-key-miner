// 证明: CIOS 特形 REDC 行(零乘法) == 参考 CIOS(位级)
// P limb 形状 [ff,ff,ff,00,00,00,01,ff] 的利用:
//   j=0: m*P[0] + t[0] = (m<<32) - m + m = m<<32  =>  c0 = m (零乘法!)
//   j=1,2: m*P[j] = (m<<32) - m
//   j=3,4,5: m*P[j] = 0
//   j=6:   m*P[6] = m
//   j=7:   m*P[7] = (m<<32) - m
import crypto from 'node:crypto';
const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const MASK32 = 0xffffffffn;
const P = [0xffffffffn, 0xffffffffn, 0xffffffffn, 0n, 0n, 0n, 1n, 0xffffffffn];
const fromLimbs = (l) => l.reduce((acc, x, i) => acc + (x << BigInt(32 * i)), 0n);
const toLimbs8 = (v) => { const o = []; for (let i = 0; i < 8; i++) { o.push(v & MASK32); v >>= 32n; } return o; };
const rand32 = () => BigInt('0x' + crypto.randomBytes(32).toString('hex')) % p;
const M32 = 1n << 32n;

function fpMulSpecial(a, b) {
  const t = new Array(10).fill(0n);
  for (let i = 0; i < 8; i++) {
    // 乘法行
    let c = 0n;
    for (let j = 0; j < 8; j++) {
      const s = a[i] * b[j] + t[j] + c;
      t[j] = s & MASK32;
      c = s >> 32n;
    }
    let s = t[8] + c;
    t[8] = s & MASK32;
    t[9] += s >> 32n;
    // ---- 特形 REDC 行 (零乘法) ----
    const m = t[0];
    // j=0: c = (m*P[0] + t[0]) >> 32 = ((m<<32) - m + m) >> 32 = m
    c = m;
    // j=1,2: m*P[j] = (m<<32) - m; 合并 c(=m): s2 = (m<<32) - m + t[j] + m = (m<<32) + t[j]
    //   注意不能再加 c (它已被合并)! c_out = s2 >> 32 = m + floor(t[j]/2^32) = m (t[j]<2^32)
    {
      const s2 = (m << 32n) + t[1];
      t[0] = s2 & MASK32;
      c = m;
    }
    {
      const s2 = (m << 32n) + t[2] + c;   // c 此处不再是 m: 上一行已输出 t[0] 的新值
      // 重算: j=2 的进位输入 = j=1 的 c_out = m。 s2 = (m<<32) - m + t[2] + m = (m<<32) + t[2]
      const s2b = (m << 32n) + t[2];
      t[1] = s2b & MASK32;
      c = m;
    }
    // j=3..5: 纯进位传播
    for (let j = 3; j <= 5; j++) {
      const s2 = t[j] + c;
      t[j - 1] = s2 & MASK32;
      c = s2 >> 32n;
    }
    // j=6: m + t[6] + c
    {
      const s2 = m + t[6] + c;
      t[5] = s2 & MASK32;
      c = s2 >> 32n;
    }
    // j=7: (m<<32) - m + t[7] + c
    {
      const s2 = (m << 32n) - m + t[7] + c;
      t[6] = s2 & MASK32;
      c = s2 >> 32n;
    }
    s = t[8] + c;
    t[7] = s & MASK32;
    t[8] = t[9] + (s >> 32n);
    t[9] = 0n;
  }
  // 条件减 p
  const tmp = new Array(8);
  let borrow = 0n;
  for (let i = 0; i < 8; i++) {
    const d = t[i] - P[i] - borrow;
    tmp[i] = d & MASK32;
    borrow = (d >> 63n) & 1n;
  }
  const ge = t[8] !== 0n || borrow === 0n;
  const v = ge ? fromLimbs(tmp) : fromLimbs(t.slice(0, 8));
  return toLimbs8(v);
}

// 参考: a*b*R^-1 mod p
const Rinv = (() => {
  let [r0, r1, s0, s1] = [p, 1n << 256n, 0n, 1n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return ((s0 % p) + p) % p;
})();
const refMont = (a, b) => (a * b * Rinv) % p;

const cases = [];
for (let i = 0; i < 200000; i++) cases.push([rand32(), rand32()]);
cases.push([p - 1n, p - 1n], [1n, 1n], [0n, 0n]);
let fails = 0;
for (const [a, b] of cases) {
  const got = fromLimbs(fpMulSpecial(toLimbs8(a), toLimbs8(b)));
  const ref = refMont(a, b);
  if (got !== ref) {
    fails++;
    if (fails <= 3) console.log('FAIL', a.toString(16).slice(0, 12), b.toString(16).slice(0, 12), got.toString(16), ref.toString(16));
  }
}
console.log(fails === 0
  ? `SPECIAL REDC: ALL PASS (${cases.length}) — zero-multiply REDC row is bit-exact`
  : `FAILED: ${fails}`);
process.exit(fails === 0 ? 0 : 1);
