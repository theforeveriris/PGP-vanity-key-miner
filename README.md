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
