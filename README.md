# PGP Vanity Key Miner

一个用于生成具有特殊指纹的 PGP 密钥对的全栈 Web 应用。

> **项目来源**：本项目最初脱胎于 [theforeveriris/Plan-for-Vibe-Coding](https://github.com/theforeveriris/Plan-for-Vibe-Coding) 的项目实例部分，现已独立维护。以后所有提交均在此仓库进行。

## 项目概述

PGP Vanity Key Miner 是一个类似于加密货币 vanity address 生成器的工具，但专门针对 OpenPGP 公钥指纹/ID。它可以批量生成 PGP 密钥对，并筛选出具有特殊模式的公钥。

### 核心功能

- **多规则筛选**：支持连续数字、重复数字、回文、特殊日期、自定义正则和前导零等多种筛选规则
- **多线程挖掘**：使用 Worker 线程实现并行密钥生成，提高挖掘效率
- **实时进度推送**：通过 SSE (Server-Sent Events) 实现服务器向客户端的实时进度推送
- **数据持久化**：使用 SQLite 存储密钥元数据（不存储私钥，确保安全性）
- **完整的前端界面**：包含控制面板、实时终端、统计面板和密钥卡片展示

## 技术栈

| 类别 | 技术 | 版本 |
|------|------|------|
| 后端 | Next.js | 14+ |
| 后端 | node-openpgp | 6.0.0 |
| 后端 | better-sqlite3 | 9.4.3 |
| 前端 | Vue 3 | 3.4+ |
| 前端 | TypeScript | 5.2.2 |
| 前端 | TailwindCSS | 3.4.4 |
| 前端 | Pinia | 2.1.7 |
| 前端 | Chart.js | 4.4.8 |

## 快速开始

### 启动后端

```bash
cd backend
pnpm install
pnpm dev
```

### 启动前端

```bash
cd frontend
pnpm install
pnpm dev
```

## 项目结构

```
.
├── backend/          # Next.js 后端
│   ├── app/
│   │   ├── api/      # API 路由
│   │   ├── lib/      # 核心库
│   │   └── workers/  # Worker 线程
│   └── package.json
├── frontend/         # Vue 3 前端
│   ├── src/
│   │   ├── components/  # 组件
│   │   ├── stores/      # 状态管理
│   │   └── views/       # 页面
│   └── package.json
└── README.md
```

## API 接口

### 1. 启动挖掘任务
- **端点**：`POST /api/miner/start`
- **参数**：
  ```json
  {
    "patternType": "consecutive",
    "patternConfig": {
      "minLength": 5
    },
    "threads": 4
  }
  ```

### 2. 停止挖掘任务
- **端点**：`POST /api/miner/stop/:taskId`

### 3. 实时流
- **端点**：`GET /api/miner/stream/:taskId`
- **返回**：SSE 流，包含进度和匹配信息

### 4. 获取密钥列表
- **端点**：`GET /api/keys`

## 筛选规则

| 规则名称 | 描述 | 配置参数 |
|---------|------|----------|
| `consecutive` | 连续数字 | `minLength` (最小长度) |
| `repeating` | 重复数字 | `minLength` (最小长度) |
| `palindrome` | 回文数字 | 无 |
| `special_date` | 特殊日期 | `pattern` (YYYYMMDD 格式) |
| `custom_regex` | 自定义正则 | `pattern` (正则表达式) |
| `leading_zeros` | 前导零 | `zeroCount` (零的数量) |

## 安全注意事项

- **私钥安全**：私钥不会存储在数据库中，仅在生成时提供下载，请妥善保管
- **密钥强度**：默认使用 2048 位 RSA 密钥，可根据需要在代码中调整
- **网络安全**：在生产环境部署时，建议使用 HTTPS 保护 API 通信

## 许可证

MIT License

## GPU 加速引擎 (CUDA)

v5 优化后(GTX 1650 实测):

| 引擎 | 速率 | 说明 |
|------|------|------|
| CPU 单线程 | ~6.2k keys/s | 参考基线 |
| CPU 满载 (6 workers) | ~37k keys/s | 6× |
| GPU v1 | ~700k keys/s | 主机预筛,逐批回传 700KB |
| GPU v2 | ~838k keys/s | GPU 侧规则预筛 + 1M/批 |
| **GPU v5** | **~952k keys/s (纯算) / ~891k/s (含命中处理)** | **融合 ChaCha RNG + 单 kernel + 双槽事件流水线** |

### v5 架构变化

- **CPU↔GPU 流量 32MB/批 → 64B/批**: 标量不再由 CPU 生成上传——每批主机只上传 48 字节 OS CSPRNG 种子(BCryptGenRandom),内核内 ChaCha8(RFC 8439 向量验证)逐线程派生标量。计数器空间 (batchIdx·2^22 + threadIdx) 会话内不复用
- **单 kernel 融合**: RNG → 标量乘 → SHA-1 → keyId → 规则预筛 → 命中数据(d/x/y/kid)内核内压实,消除中间 64MB 全局内存往返与第二 kernel 启动
- **双槽事件流水线**: 两批 kernel 常驻 GPU 队列,主机仅同步 4B hitCount 事件,CPU 不再阻塞 GPU(GPU 永不空转等主机)
- **零乘法 REDC 行**: CIOS 蒙哥马利乘的归约行利用 P-256 素数 limb 形状 [ff,ff,ff,00,00,00,01,ff] 全部化为移位/加减(证明: gpu/verify_specialred.mjs 200k 用例位级比对),域乘 ~-50% 多项式开销
- **未采纳(实测记录)**: plain 域特形约减(335k/s,12 轮折叠过重)、warp 批量求逆(736k/s,SIMT 下 32 lane 冗余费马链无净收益)——两者均经 42 向量位级验证正确,纯属吞吐回退,代码见 git 历史与 gpu/verify_*.mjs 证明脚本
- **启动自检 + 零信任复验不变**: 1G/2G 常数比对 → OpenSSL 曲线一致性 → 指纹重算 → 真实 JS 规则引擎,全过才落库

### 支持的 GPU 规则类型

`consecutive` / `repeating` / `palindrome` / `leading_zeros` / `special_date` / `custom_regex`(可提取必需字面量的正则);规则数 ≤8;超出或无字面量正则自动回落 CPU。

### 正确性验证

- 42 标量(边界+随机)与 OpenSSL 位级完全一致 (x, y, keyId);实挖命中经 BigInt 参考标量乘交叉一致 (test_consistency.mjs)
- 零乘 REDC 行: verify_specialred.mjs 200k 随机对标量级比对 == 参考 CIOS
- ChaCha8: RFC 8439 2.3.2 测试向量 + node:crypto keystream 双重验证
- 实挖命中经零信任链复验全绿并落库

### 重编译

```powershell
cd backend/gpu
$env:CUDA_ROOT = '<cuda toolkit path>'   # 例如 D:\ZcodeData\downloads\cuda135
powershell -ExecutionPolicy Bypass -File build.ps1
```

注意: CUDA 源码必须纯 ASCII (nvcc/cicc 在 cp936 代码页下会把 UTF-8 注释误读吞换行)。
