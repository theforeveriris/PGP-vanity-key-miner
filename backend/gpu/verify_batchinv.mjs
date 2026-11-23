// warp-level Montgomery batch inversion proof (32 lanes; zero-safe)
import crypto from 'node:crypto';
const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const modInv = (v) => { let [r0, r1, s0, s1] = [p, ((v % p) + p) % p, 0n, 1n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return ((s0 % p) + p) % p; };
function warpBatchInv(v) {
  const lanes = v.map((x) => (x === 0n ? 1n : x));
  const prod = lanes.slice();
  for (let d = 1; d < 32; d <<= 1) {
    const tmp = prod.slice();
    for (let i = 0; i < 32; i++) if (i >= d) tmp[i] = (prod[i] * prod[i - d]) % p;
    for (let i = 0; i < 32; i++) prod[i] = tmp[i];
  }
  let t = modInv(prod[31]);
  const inv = new Array(32).fill(0n);
  for (let i = 31; i >= 1; i--) {
    inv[i] = (prod[i - 1] * t) % p;
    t = (t * lanes[i]) % p;
  }
  inv[0] = t;
  for (let i = 0; i < 32; i++) if (v[i] === 0n) inv[i] = 0n;
  return inv;
}
let fails = 0;
for (let round = 0; round < 2000; round++) {
  const v = [];
  for (let i = 0; i < 32; i++) {
    let x = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % p;
    if (round % 7 === 3 && i % 9 === 4) x = 0n;
    v.push(x);
  }
  const inv = warpBatchInv(v);
  for (let i = 0; i < 32; i++) {
    const expect = v[i] === 0n ? 0n : modInv(v[i]);
    if (inv[i] !== expect) { fails++; if (fails <= 3) console.log('FAIL lane', i); }
  }
}
console.log(fails === 0 ? 'BATCH INV: ALL PASS (2000 warps x 32 lanes, incl. zero handling)' : 'FAILED: ' + fails);
process.exit(fails === 0 ? 0 : 1);
