// Primitive-layer debug kernel: verify Montgomery ops / constants / table points on device
#include <cstdio>
#include <cstdint>
#include "p256.cuh"
#include "sha1.cuh"

__device__ void to_hex(const u32 v[8], char* out) {
    const char* H = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {          // limb index, BE order
        u32 w = v[7 - i];
        for (int b = 0; b < 8; b++) {      // nibbles MSB-first within limb
            out[i * 8 + b] = H[(w >> (28 - 4 * b)) & 0xF];
        }
    }
    out[64] = 0;
}

__global__ void dbg_kernel() {
    if (threadIdx.x != 0 || blockIdx.x != 0) return;
    char buf[65];
    u32 t[LIMBS];

    // T1: fp_mul(MONT_ONE, MONT_ONE) == MONT_ONE (unity inside Montgomery domain)
    fp_mul(P256_MONT_ONE, P256_MONT_ONE, t);
    to_hex(t, buf); printf("T1 mont_one*mont_one = %s\n", buf);

    // T2: fp_mul(P256_R2, P256_ONE) == MONT_ONE  (R2 * 1 * R^-1 = R, converts plain 1 to mont)
    fp_mul(P256_R2, P256_ONE, t);
    to_hex(t, buf); printf("T2 R2*plain1 = %s\n", buf);

    // T3: fp_inv(MONT_ONE) == MONT_ONE
    u32 a[LIMBS]; fp_copy(P256_MONT_ONE, a);
    u32 inv[LIMBS]; fp_inv(a, inv);
    to_hex(inv, buf); printf("T3 inv(mont_one) = %s\n", buf);

    // T4: table point 1G on curve? y^2 ?= x^3 - 3x + b  (all in Montgomery domain)
    u32 x[LIMBS], y[LIMBS];
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) { x[i] = P256_GX[i]; y[i] = P256_GY[i]; }
    u32 lhs[LIMBS], rhs[LIMBS], xx[LIMBS], t3[LIMBS];
    fp_sqr(y, lhs);                                       // y^2
    fp_sqr(x, xx); fp_mul(xx, x, xx);                     // x^3
    u32 three[LIMBS] = {3u, 0, 0, 0, 0, 0, 0, 0};
    fp_mul(x, three, t3);                                 // 3x
    fp_sub(xx, t3, rhs);                                  // x^3 - 3x
    fp_add(rhs, P256_B, rhs);                             // + b
    to_hex(lhs, buf); printf("T4 y^2        = %s\n", buf);
    to_hex(rhs, buf); printf("T4 x^3-3x+b  = %s\n", buf);

    // T5: scalar 1 -> full pipeline (shared-memory path needs a full block, launch separately)
}

__global__ void dbg_sha1_kernel() {
    if (threadIdx.x != 0 || blockIdx.x != 0) return;
    // d=1 -> G, created=1735564800; JS reference kid = d91ecdd5200deefa
    uint8_t X[32] = {0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
                     0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96};
    uint8_t Y[32] = {0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
                     0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
    uint32_t kid[2];
    pgp_keyid(X, Y, 1735564800u, kid);
    char k[17];
    const char* H = "0123456789abcdef";
    for (int b = 0; b < 8; b++) {
        uint32_t w = (b < 4) ? kid[0] : kid[1];
        int sh = 24 - 8 * (b % 4);
        k[2 * b]     = H[(w >> (sh + 4)) & 0xF];
        k[2 * b + 1] = H[(w >> sh) & 0xF];
    }
    k[16] = 0;
    printf("T6 kid = %s (expect d91ecdd5200deefa)\n", k);
}

__global__ void dbg_scalar1_kernel() {
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
    if (threadIdx.x != 0) return;
    uint8_t scalar[32] = {0};
    scalar[0] = 1;
    u32 X[LIMBS], Y[LIMBS];
    scalar_mul_G(scalar, X, Y);
    u32 px[LIMBS], py[LIMBS];
    fp_from_mont(X, px);
    fp_from_mont(Y, py);
    char bx[65], by[65];
    to_hex(px, bx); to_hex(py, by);
    printf("T5 d=1 x = %s\nT5 d=1 y = %s\n", bx, by);
}

int main() {
    dbg_kernel<<<1, 1>>>();
    cudaDeviceSynchronize();
    dbg_sha1_kernel<<<1, 1>>>();
    cudaError_t e1 = cudaDeviceSynchronize();
    printf("sync after sha1: %s\n", cudaGetErrorString(e1));
    dbg_scalar1_kernel<<<1, 32>>>();
    cudaDeviceSynchronize();
    cudaError_t e = cudaGetLastError();
    if (e != cudaSuccess) printf("CUDA error: %s\n", cudaGetErrorString(e));
    return 0;
}
