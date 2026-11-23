// P-256 Montgomery field arithmetic + Jacobian scalar multiplication (CUDA device code)
//
// v4 design (perf overhaul, REDC-row math proven in verify_specialred.mjs 200003/200003):
//   - CIOS Montgomery multiplication, but the REDC row is ZERO-MULTIPLY:
//     p's limb shape [ff,ff,ff,00,00,00,01,ff] gives
//       m*P[0] + t[0] = m<<32          -> carry in = m (exact identity)
//       m*P[1..2]    = (m<<32) - m     -> merged with carry m: s2 = (m<<32) + t[j], c_out = m
//       m*P[3..5]    = 0               -> pure carry propagation
//       m*P[6]       = m
//       m*P[7]       = (m<<32) - m
//     fp_mul = 64 MACs (multiply row) + ~14 shift/add ops (REDC row) instead of
//     64 + 64 MACs. (A plain-domain special-form fold was tried in v3: measured
//     335k/s vs 710k/s -- its 12-round fold loop is far heavier. Reverted.)
//   - All values canonical Montgomery (< p); alias-safe (locals + final commit).
//   - 4-bit windows; table 1G..15G affine Montgomery in __constant__, shared copy.
//   - Fermat inversion: Montgomery unity is P256_MONT_ONE (= R mod p), NOT plain 1.
//   - ASCII-only source: nvcc/cicc misreads UTF-8 comments on cp936 codepage systems.
#pragma once
#include <cstdint>
#include "p256_constants.h"

#define LIMBS 8

// ---------- basic field ops ----------
__device__ __forceinline__ void fp_copy(const u32 src[LIMBS], u32 dst[LIMBS]) {
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) dst[i] = src[i];
}

__device__ __forceinline__ bool fp_is_zero(const u32 a[LIMBS]) {
    u32 r = 0;
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) r |= a[i];
    return r == 0;
}

// add: out = a + b (mod p); inputs canonical
__device__ __forceinline__ void fp_add(const u32 a[LIMBS], const u32 b[LIMBS], u32 out[LIMBS]) {
    u64 c = 0;
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) {
        c += (u64)a[i] + b[i];
        out[i] = (u32)c;
        c >>= 32;
    }
    u64 borrow = 0;
    u32 tmp[LIMBS];
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) {
        u64 d = (u64)out[i] - P256_P[i] - borrow;
        tmp[i] = (u32)d;
        borrow = (d >> 63) & 1;
    }
    if (c != 0 || borrow == 0) fp_copy(tmp, out);
}

// sub: out = a - b (mod p); inputs canonical
__device__ __forceinline__ void fp_sub(const u32 a[LIMBS], const u32 b[LIMBS], u32 out[LIMBS]) {
    u64 borrow = 0;
    u32 tmp[LIMBS];
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) {
        u64 d = (u64)a[i] - b[i] - borrow;
        tmp[i] = (u32)d;
        borrow = (d >> 63) & 1;
    }
    if (borrow) {
        u64 c = 0;
        #pragma unroll
        for (int i = 0; i < LIMBS; i++) {
            c += (u64)tmp[i] + P256_P[i];
            tmp[i] = (u32)c;
            c >>= 32;
        }
    }
    fp_copy(tmp, out);
}

// Montgomery multiplication (CIOS, s=8, n0=1) with zero-multiply REDC row.
// r = a*b*R^-1 mod p; alias-safe (r may equal a or b).
__device__ __forceinline__ void fp_mul(const u32 a[LIMBS], const u32 b[LIMBS], u32 r[LIMBS]) {
    u32 t[LIMBS + 2] = {0};
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) {
        // row 1: t += a[i] * b
        u64 c = 0;
        #pragma unroll
        for (int j = 0; j < LIMBS; j++) {
            u64 s = (u64)a[i] * b[j] + t[j] + c;
            t[j] = (u32)s;
            c = s >> 32;
        }
        u64 s = (u64)t[LIMBS] + c;
        t[LIMBS] = (u32)s;
        t[LIMBS + 1] += (u32)(s >> 32);

        // row 2: special-form REDC (n0 == 1 => m = t[0]); zero multiplies.
        // j=0: m*P[0] + t[0] = (m<<32) - m + m = m<<32 -> carry = m
        // j=1,2: m*P[j] = (m<<32) - m; with carry m merged: s2 = (m<<32) + t[j],
        //        carry out = m + t[j]/2^32 = m (t[j] < 2^32 exactly)
        // j=3..5: m*P[j] = 0 -> pure carry chain
        // j=6: m*P[6] = m
        // j=7: m*P[7] = (m<<32) - m
        u32 m = t[0];
        // row 2 (REDC): reuse the dead `c` from row 1.
        // j=0: (m*P[0] + t[0]) >> 32 = ((m<<32) - m + m) >> 32 = m
        c = m;
        {
            u64 s2 = ((u64)m << 32) + t[1];   // m*P[1] + t[1] + c, with -m and c(=m) merged
            t[0] = (u32)s2;
            c = m;   // carry out = ((m<<32) + t[1]) >> 32 == m since t[1] < 2^32
        }
        {
            u64 s2 = ((u64)m << 32) + t[2];   // -m and carry(=m) merged again: no +c!
            t[1] = (u32)s2;
            c = m;   // carry out is exactly m (t[2] < 2^32)
        }
        #pragma unroll
        for (int j = 3; j <= 5; j++) {
            u64 s2 = (u64)t[j] + c;
            t[j - 1] = (u32)s2;
            c = s2 >> 32;
        }
        {
            u64 s2 = (u64)m + t[6] + c;
            t[5] = (u32)s2;
            c = s2 >> 32;
        }
        {
            u64 s2 = ((u64)m << 32) - m + t[7] + c;
            t[6] = (u32)s2;
            c = s2 >> 32;
        }
        u64 s3 = (u64)t[LIMBS] + c;
        t[LIMBS - 1] = (u32)s3;
        t[LIMBS] = t[LIMBS + 1] + (u32)(s3 >> 32);
        t[LIMBS + 1] = 0;
    }
    // final conditional subtract p (t may be >= p)
    u32 tmp[LIMBS];
    u64 borrow = 0;
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) {
        u64 d = (u64)t[i] - P256_P[i] - borrow;
        tmp[i] = (u32)d;
        borrow = (d >> 63) & 1;
    }
    bool ge = (t[LIMBS] != 0) || (borrow == 0);
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) r[i] = ge ? tmp[i] : t[i];
}

__device__ __forceinline__ void fp_sqr(const u32 a[LIMBS], u32 r[LIMBS]) { fp_mul(a, a, r); }

// a^(p-2) mod p, Fermat inversion (values in Montgomery domain)
__device__ __forceinline__ void fp_inv(u32 a[LIMBS], u32 r[LIMBS]) {
    u32 e[LIMBS];
    u32 two[LIMBS] = {2u, 0, 0, 0, 0, 0, 0, 0};
    fp_sub(P256_P, two, e);
    u32 result[LIMBS];
    fp_copy(P256_MONT_ONE, result); // Montgomery unity = R mod p (plain 1 would corrupt everything)
    bool started = false;
    for (int i = LIMBS * 32 - 1; i >= 0; i--) {
        u32 bit = (e[i / 32] >> (i % 32)) & 1u;
        if (started) {
            fp_sqr(result, result);
            if (bit) fp_mul(result, a, result);
        } else if (bit) {
            fp_copy(a, result);
            started = true;
        }
    }
    fp_copy(result, r);
}

// ---------- Jacobian point arithmetic (coordinates in Montgomery domain) ----------
struct Jac {
    u32 X[LIMBS], Y[LIMBS], Z[LIMBS];
};

// Doubling (a=-3): M = 3(X-Z^2)(X+Z^2), S=4XY^2, X3=M^2-2S, Y3=M(S-X3)-8Y^4, Z3=2YZ
// Alias-safe: no writes into R until the final commit.
__device__ __forceinline__ void pt_dbl(const Jac& P, Jac& R) {
    u32 z2[LIMBS], m[LIMBS], s[LIMBS], t[LIMBS], y2[LIMBS], x3[LIMBS], y3[LIMBS], z3[LIMBS];
    fp_sqr(P.Z, z2);                     // Delta = Z^2
    fp_sub(P.X, z2, t);                  // X - Delta
    fp_add(P.X, z2, z3);                 // X + Delta
    fp_mul(t, z3, m);                    // (X-Delta)(X+Delta)
    fp_add(m, m, s);
    fp_add(m, s, m);                     // M = 3(X-Delta)(X+Delta)
    fp_sqr(P.Y, y2);                     // Y^2 (kept for 8Y^4)
    fp_mul(y2, P.X, t);                  // X*Y^2
    fp_add(t, t, s);
    fp_add(s, s, s);                     // S = 4XY^2
    fp_sqr(m, x3);                       // M^2
    fp_sub(x3, s, t);
    fp_sub(t, s, x3);                    // X3 = M^2 - 2S
    fp_sub(s, x3, t);                    // S - X3
    fp_mul(m, t, y3);                    // M(S - X3)
    fp_sqr(y2, z2);                      // Y^4
    fp_add(z2, z2, t);
    fp_add(t, t, t);
    fp_add(t, t, t);                     // 8Y^4
    fp_sub(y3, t, y3);                   // Y3 = M(S-X3) - 8Y^4
    fp_mul(P.Y, P.Z, z3);                // Y*Z (P.Y/P.Z still original: nothing written yet)
    fp_add(z3, z3, z3);                  // Z3 = 2YZ
    fp_copy(x3, R.X);
    fp_copy(y3, R.Y);
    fp_copy(z3, R.Z);
}

// Mixed addition: Jacobian P + affine (x2,y2). Alias-safe (R may equal P).
// EFD madd-2007-bl (Z2=1), 8M+3S; numerically validated in JS (verify_formula.mjs).
__device__ __forceinline__ void pt_madd(const Jac& P, const u32 x2[LIMBS], const u32 y2[LIMBS], Jac& R) {
    u32 zz[LIMBS], u2[LIMBS], s2[LIMBS], h[LIMBS], i_[LIMBS], J[LIMBS], r[LIMBS], V[LIMBS];
    u32 x3[LIMBS], y3[LIMBS], z3[LIMBS], t[LIMBS];
    fp_sqr(P.Z, zz);                     // Z1Z1 = Z1^2
    fp_mul(x2, zz, u2);                  // U2 = x2*Z1Z1
    fp_mul(y2, zz, s2);                  // y2*Z1Z1
    fp_mul(s2, P.Z, s2);                 // S2 = y2*Z1*Z1Z1
    fp_sub(u2, P.X, h);                  // H = U2 - X1
    fp_add(h, h, i_);                    // 2*H
    fp_sqr(i_, i_);                      // I = (2H)^2
    fp_mul(h, i_, J);                    // J = H*I
    fp_sub(s2, P.Y, r);                  // S2 - Y1
    fp_add(r, r, r);                     // r = 2*(S2 - Y1)
    fp_mul(P.X, i_, V);                  // V = X1*I
    fp_sqr(r, x3);                       // r^2
    fp_sub(x3, J, t);
    fp_sub(t, V, t);
    fp_sub(t, V, x3);                    // X3 = r^2 - J - 2V
    fp_sub(V, x3, t);                    // V - X3
    fp_mul(r, t, y3);                    // r*(V - X3)
    fp_mul(P.Y, J, t);                   // Y1*J
    fp_add(t, t, t);                     // 2*Y1*J
    fp_sub(y3, t, y3);                   // Y3
    fp_add(P.Z, P.Z, t);                 // 2*Z1
    fp_mul(t, h, z3);                    // Z3 = 2*Z1*H
    fp_copy(x3, R.X);
    fp_copy(y3, R.Y);
    fp_copy(z3, R.Z);
}

// ---------- scalar multiplication driver ----------
// Table P256_GX/P256_GY is Montgomery-domain affine (p256_constants.h);
// each block copies it to __shared__ first (dynamic random indexing into
// __constant__ memory is hardware-serialized; __shared__ has no such penalty).

// d: 32-byte little-endian scalar; outputs affine X,Y in Montgomery domain
__device__ __forceinline__ void scalar_mul_G(const uint8_t scalar[32], u32 outX[LIMBS], u32 outY[LIMBS]) {
    __shared__ u32 sGX[15][LIMBS];
    __shared__ u32 sGY[15][LIMBS];
    if (threadIdx.x < 15) {
        #pragma unroll
        for (int i = 0; i < LIMBS; i++) {
            sGX[threadIdx.x][i] = P256_GX[threadIdx.x * LIMBS + i];
            sGY[threadIdx.x][i] = P256_GY[threadIdx.x * LIMBS + i];
        }
    }
    __syncthreads();
    int top = (scalar[31] >> 4) & 0xF;
    Jac acc;
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) { acc.X[i] = 0; acc.Y[i] = 0; acc.Z[i] = 0; }
    if (top != 0) {
        #pragma unroll
        for (int i = 0; i < LIMBS; i++) {
            acc.X[i] = sGX[top - 1][i];
            acc.Y[i] = sGY[top - 1][i];
        }
        fp_copy(P256_MONT_ONE, acc.Z);  // Montgomery unity
    }
    bool started = top != 0;

    for (int k = 62; k >= 0; k--) {
        if (started) {
            #pragma unroll
            for (int j = 0; j < 4; j++) pt_dbl(acc, acc);
        }
        u32 limb = scalar[k >> 1];
        int nib = (k & 1) ? (limb >> 4) & 0xF : limb & 0xF;
        if (nib != 0) {
            if (!started) {
                #pragma unroll
                for (int i = 0; i < LIMBS; i++) {
                    acc.X[i] = sGX[nib - 1][i];
                    acc.Y[i] = sGY[nib - 1][i];
                }
                fp_copy(P256_MONT_ONE, acc.Z);
                started = true;
            } else {
                pt_madd(acc, sGX[nib - 1], sGY[nib - 1], acc);
            }
        }
    }

    // affine conversion: z_inv = Z^(p-2), x = X*z^2, y = Y*z^3 (Montgomery domain)
    // NOTE: per-thread Fermat is optimal on SIMT (all lanes fully busy on their
    // own 385-mul chain). A warp-cooperative batch inversion was implemented and
    // benchmarked at 736k/s vs 896k/s -- redundant lane work + scan overhead make
    // it a regression on GPU (it is a latency/CPU optimization, not throughput).
    if (fp_is_zero(acc.Z)) {
        #pragma unroll
        for (int i = 0; i < LIMBS; i++) { outX[i] = 0; outY[i] = 0; }
        return;
    }
    u32 zinv[LIMBS], z2[LIMBS], z3[LIMBS];
    fp_inv(acc.Z, zinv);
    fp_sqr(zinv, z2);
    fp_mul(z2, zinv, z3);
    fp_mul(acc.X, z2, outX);
    fp_mul(acc.Y, z3, outY);
}

// Montgomery domain -> plain integer: mont_mul(x, 1)
__device__ __forceinline__ void fp_from_mont(const u32 x[LIMBS], u32 r[LIMBS]) {
    u32 one[LIMBS] = {1u, 0, 0, 0, 0, 0, 0, 0};
    fp_mul(x, one, r);
}
