# 后端入口文件

## 目录结构说明

此目录为后端 Next.js 应用程序的根目录。

### 目录结构

```
backend/
|-- app/                    # Next.js App Router
|   |-- api/               # API 路由
|   |-- lib/               # 库文件
|   |-- workers/           # Worker 线程
|-- prisma/ or schemas/    # 数据库 schema（如使用 ORM）
|-- package.json
|-- tsconfig.json
```

### 主要文件

- `app/layout.tsx` - 根布局
- `app/page.tsx` - 根页面
- `app/api/*/route.ts` - API 路由

### 启动方式

```bash
cd backend
pnpm install
pnpm dev
```

### 环境变量

在 `backend/` 目录创建 `.env` 文件：

```env
DATABASE_URL=./data/miner.db
```
## GPU 加速(CUDA 引擎,可选)

在 CPU 引擎之外,后端支持可选的 GPU(CUDA)挖掘引擎。架构:单融合内核执行全部
热点(ChaCha8 标量派生 → P-256 标量乘法 → SHA-1 → keyId → 规则预筛 → 命中压实),
主机每批仅上传 48 字节 OS CSPRNG 种子(BCryptGenRandom)、下载 4B 命中计数与少量
命中记录;每条命中回传 `(d, x, y, created)` 给 Node 端做零信任复验(JWK 一致性
校验 → 指纹重算 → 真实规则引擎复验),复验通过才走 openpgp 组装与落库。规则语义
与 CPU 引擎零偏移。两批 kernel 双槽流水,主机永不阻塞 GPU。

实测(i5-10300H + GTX 1650):CPU ~6.2k keys/s/线程(8 线程 ~37k/s),GPU ~952k
keys/s 纯算(~891k/s 含命中处理,约为满载 CPU 的 24 倍)。规则不支持 GPU 预筛时
(如无必需字面量的正则)自动回落 CPU。

### 安全要点

- 标量随机性:每批 48 字节种子来自 OS CSPRNG(BCryptGenRandom),内核内 ChaCha8
  (RFC 8439 向量验证)按 (batchIdx, threadIdx) 唯一计数器派生,会话内计数器不复用;
  种子不出主机,标量全程驻留 GPU(仅命中时回传)
- 每条 GPU 命中在 Node 端完整复验后才落库,GPU 输出的任何单字段都不可信

### 构建 GPU 引擎

依赖:MSVC v143(x64)+ CUDA Toolkit(sm_75 及以上)。工具链通过环境变量定位:

```powershell
# backend/gpu 目录下
$env:CUDA_ROOT = "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.5"  # 按实际路径
powershell -ExecutionPolicy Bypass -File build.ps1
```

产物 `pgp_gpu_miner.exe` 需与 `app/workers/gpu.worker.mjs` 配合,由任务管理器在
`engine: "gpu"` 时拉起(stdin 关闭即自动退出,不会产生孤儿进程)。

### 正确性保障(回归测试,均在 backend 下运行)

```bash
node gpu/test_gpu.mjs      # GPU vs node:crypto(OpenSSL)位级比对(随机+边界标量)
node gpu/test_extract.mjs  # 正则字面量提取算法(12 用例 + 2 万次随机 soundness 交叉验证)
node gpu/test_rebuild.mjs  # 命中重建链:JWK 校验 → 指纹 → openpgp 组装 → 签名/加解密
```

### 字节序约定

- 内核内所有域元素为 8×32 位小端 limb(Montgomery 域)
- 标量 d、坐标 x/y、指纹 keyId 的 hex 输入输出一律为标准大端表示
  (JWK 的 `d`/`x`/`y` 字段直接可用,无需转换)

### 安全要点

- GPU 批量随机数来自 OS CSPRNG(BCryptGenRandom),不做弱种子
- 每条 GPU 命中在 Node 端完整复验后才落库,GPU 输出的任何单字段都不可信
