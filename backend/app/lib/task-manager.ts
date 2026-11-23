// 任务管理器
import { v4 as uuidv4 } from 'uuid';
import { Worker } from 'worker_threads';
import path from 'path';
import type { MiningTask, PatternRule, RuleGroup, KeyPair, SpecialKey, SSEMessage } from './pgp/types';
import { createTask, updateTaskProgress, stopTask, getTask, createSpecialKey, savePrivateKey } from './db/queries';

// Worker 线程入口（纯 JS，避免运行时 TS 编译依赖）
const WORKER_PATH = path.join(process.cwd(), 'app', 'workers', 'mining.worker.mjs');
const GPU_WORKER_PATH = path.join(process.cwd(), 'app', 'workers', 'gpu.worker.mjs');

export type Engine = 'cpu' | 'gpu';

// 匹配消息推送限流（条/秒，以及允许的突发量）
const MAX_MATCH_PER_SEC = 20;
const MAX_MATCH_BURST = 40;

interface WorkerInfo {
  taskId: string;
  workerId: string;
  worker: Worker;
  attempts: number;
  hashrate: number;
  matches: number;
  startTime: number;
  lastUpdateTime: number;
  lastAttempts: number;
  alive: boolean;
  engine: Engine;
}

class TaskManager {
  private tasks: Map<string, MiningTask> = new Map();
  private workers: Map<string, WorkerInfo> = new Map();
  private sseClients: Map<string, Set<(message: SSEMessage) => void>> = new Map();
  // 每个任务上次写数据库的时间（用于节流）
  private lastDbWrite: Map<string, number> = new Map();
  // 待广播进度的任务集合
  private pendingProgress: Set<string> = new Set();
  // 聚合广播定时器
  private progressTimer: ReturnType<typeof setInterval> | null = null;
  // 每个任务的匹配推送令牌桶
  private matchBuckets: Map<string, { tokens: number; lastRefill: number }> = new Map();
  // 每个任务已落库的密钥数量（真实命中中成功补全并保存的数量）
  private archivedCounts: Map<string, number> = new Map();

  /** 某个任务已落库的密钥数量 */
  getArchivedCount(taskId: string): number {
    return this.archivedCounts.get(taskId) || 0;
  }

  constructor() {
    // 定期清理过期任务
    setInterval(() => this.cleanupTasks(), 60000);
  }

  async startTask(
    patterns: PatternRule[],
    threads: number = 4,
    logicOperator: 'AND' | 'OR' = 'OR',
    groups: RuleGroup[] = [],
    engine: Engine = 'cpu'
  ): Promise<string> {
    const taskId = uuidv4();

    // 同一时间只允许一个任务运行：先停掉旧任务，避免 Worker 线程堆积
    const runningTaskIds = Array.from(this.tasks.values())
      .filter(t => t.status === 'running')
      .map(t => t.id);
    for (const oldId of runningTaskIds) {
      console.log(`[TaskManager] 停止旧任务: ${oldId}`);
      await this.stopTask(oldId);
    }

    const task: MiningTask = {
      id: taskId,
      status: 'running',
      patterns,
      threads,
      startedAt: new Date(),
      totalAttempts: 0,
      matchesFound: 0,
      logicOperator,
      groups,
      engine,
    };

    // 保存到数据库
    createTask(task);
    this.tasks.set(taskId, task);
    this.sseClients.set(taskId, new Set());

    console.log(`[TaskManager] 任务已创建: taskId=${taskId}, engine=${engine}, patterns=${patterns.length}, groups=${groups.length}, threads=${threads}, logic=${logicOperator}`);

    // 启动真实 Worker 线程（每个线程独立 V8 isolate，可并行吃满多核）
    // GPU 引擎只有一块卡，单 worker 即可（threads 参数仅对 CPU 生效）
    if (engine === 'gpu') {
      this.startWorker(taskId, patterns, logicOperator, groups, 'gpu');
    } else {
      for (let i = 0; i < threads; i++) {
        this.startWorker(taskId, patterns, logicOperator, groups, 'cpu');
      }
    }

    return taskId;
  }

  private startWorker(
    taskId: string,
    patterns: PatternRule[],
    logicOperator: 'AND' | 'OR',
    groups: RuleGroup[],
    engine: Engine = 'cpu'
  ) {
    const workerId = `${taskId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const worker = new Worker(engine === 'gpu' ? GPU_WORKER_PATH : WORKER_PATH, {
      workerData: {
        patterns: patterns.map(p => ({
          id: p.id,
          type: p.type,
          params: p.params,
          color: p.color,
          enabled: p.enabled,
          name: p.name,
          priority: p.priority,
        })),
        logicOperator,
        groups: groups.map(g => ({
          id: g.id,
          name: g.name,
          priority: g.priority,
          enabled: g.enabled,
          logicOperator: g.logicOperator,
          rules: (g.rules || []).map(r => ({
            id: r.id,
            type: r.type,
            params: r.params,
            color: r.color,
            enabled: r.enabled,
            name: r.name,
            priority: r.priority,
          })),
          ruleRefs: g.ruleRefs,
        })),
      },
    });

    const info: WorkerInfo = {
      taskId,
      workerId,
      worker,
      attempts: 0,
      hashrate: 0,
      matches: 0,
      startTime: Date.now(),
      lastUpdateTime: Date.now(),
      lastAttempts: 0,
      alive: true,
      engine,
    };

    worker.on('message', (msg: any) => {
      try {
        this.handleWorkerMessage(taskId, info, msg);
      } catch (error) {
        // 消息处理异常不能拖垮整个 Worker 监听器
        console.error(`[TaskManager] 处理 Worker 消息失败 (${workerId}):`, error);
      }
    });

    worker.on('error', (error) => {
      console.error(`[TaskManager] Worker ${workerId} crashed:`, error);
      info.alive = false;
    });

    worker.on('exit', (code) => {
      info.alive = false;
      this.workers.delete(workerId);
      console.log(`[TaskManager] Worker 已退出: ${workerId}, code=${code}`);
    });

    this.workers.set(workerId, info);

    console.log(`[TaskManager] Worker 线程已启动: ${workerId} (threadId=${worker.threadId})`);
  }

  private handleWorkerMessage(taskId: string, info: WorkerInfo, msg: any) {
    switch (msg.type) {
      case 'progress': {
        info.attempts += msg.attempts || 0;
        info.hashrate = msg.hashrate || 0;
        info.matches = (info.matches || 0) + (msg.matchesDelta || 0);
        // 每个 Worker 各自上报，聚合后统一广播，避免重复 SSE 消息
        this.pendingProgress.add(taskId);
        if (!this.progressTimer) {
          this.progressTimer = setInterval(() => {
            this.pendingProgress.forEach((_, id) => this.updateTaskProgress(id));
            this.pendingProgress.clear();
          }, 500);
        }
        break;
      }
      case 'match': {
        // 进到这里的一定是已经补全的完整密钥（worker 只在 completeKey 成功后发送）。
        // 全部落库，保证"挖到就能下载"；SSE 只推抽中的样本，避免淹没浏览器。
        this.handleMatch(taskId, msg);
        break;
      }      case 'error': {
        console.error(`[TaskManager] Worker ${info.workerId} error: ${msg.message}`);
        break;
      }
      case 'gpu_unsupported': {
        // GPU 引擎无法处理当前规则(exe 缺失/规则不含必需字面量)——回落 CPU
        console.warn(`[TaskManager] GPU 引擎不可用(${msg.message})—— 任务 ${taskId} 回落 CPU`);
        this.fallbackToCpu(taskId);
        break;
      }
      case 'stopped': {
        info.alive = false;
        break;
      }
    }
  }

  /** GPU worker 全部退出后,用 CPU worker 重启该任务 */
  private fallbackToCpu(taskId: string) {
    const task = this.tasks.get(taskId);
    if (!task || task.status !== 'running' || task.engine === 'cpu') return;
    task.engine = 'cpu';

    const toKill: WorkerInfo[] = [];
    this.workers.forEach((info, key) => {
      if (info.taskId === taskId && info.engine === 'gpu') {
        toKill.push(info);
        this.workers.delete(key);
      }
    });
    for (const info of toKill) {
      try { info.worker.postMessage({ type: 'stop' }); } catch { /* 已退出 */ }
      try { info.worker.terminate(); } catch { /* 已退出 */ }
    }

    for (let i = 0; i < task.threads; i++) {
      this.startWorker(taskId, task.patterns, task.logicOperator || 'OR', task.groups || [], 'cpu');
    }
  }

  private updateTaskProgress(taskId: string) {
    let totalAttempts = 0;
    let totalHashrate = 0;
    let workerCount = 0;
    let totalMatches = 0;

    this.workers.forEach((info) => {
      if (info.taskId === taskId) {
        totalAttempts += info.attempts;
        totalHashrate += info.hashrate;
        totalMatches += info.matches || 0;
        workerCount++;
      }
    });

    const task = this.tasks.get(taskId);
    if (task) {
      task.totalAttempts = totalAttempts;
      task.matchesFound = totalMatches;
      this.tasks.set(taskId, task);

      // 更新数据库（节流：最多每 2 秒写一次，避免频繁重写 tasks.json）
      const now = Date.now();
      if (now - (this.lastDbWrite.get(taskId) || 0) > 2000) {
        this.lastDbWrite.set(taskId, now);
        updateTaskProgress(taskId, totalAttempts, task.matchesFound);
      }

      // 发送 SSE 消息
      const message: SSEMessage = {
        type: 'progress',
        taskId,
        attempts: totalAttempts,
        // 总算力（所有线程累加），而不是平均值
        hashrate: totalHashrate,
        matchesFound: task.matchesFound,
        archivedCount: this.archivedCounts.get(taskId) || 0,
        timestamp: Date.now(),
      };

      this.broadcastSSEMessage(taskId, message);
    }
  }

  private handleMatch(taskId: string, msg: any) {
    const task = this.tasks.get(taskId);
    if (!task) return;

    const key: KeyPair = {
      publicKey: msg.publicKey,
      privateKey: msg.privateKey,
      fingerprint: msg.fingerprint,
      keyId: msg.keyId,
    };

    // 获取匹配的规则信息
    const matchedRule = task.patterns.find(p => p.id === msg.patternId);

    // 私钥持久化保存（本机运行，方便随时下载与批量导出）
    savePrivateKey({
      keyId: key.keyId,
      fingerprint: key.fingerprint,
      privateKeyArmored: key.privateKey,
      publicKeyArmored: key.publicKey,
      createdAt: new Date().toISOString(),
      taskId,
    });

    // 保存密钥到数据库（只存公钥和元数据）
    const specialKey: SpecialKey = {
      id: `${taskId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      taskId,
      fingerprint: key.fingerprint,
      keyId: key.keyId,
      patternType: matchedRule?.type || 'consecutive',
      patternId: msg.patternId,
      matchPosition: msg.matchPosition,
      matchedText: msg.matchedText,
      attemptsToFind: msg.attempts,
      publicKeyArmored: key.publicKey,
      color: msg.color,
      createdAt: new Date(),
    };
    createSpecialKey(specialKey);
    this.archivedCounts.set(taskId, (this.archivedCounts.get(taskId) || 0) + 1);

    // SSE 只推抽中的样本：命中可能每秒上千条，全推会淹没浏览器。
    // 未抽中的已经落库，前端可通过 /api/keys 拉取。
    if (!msg.broadcast) return;

    // 匹配消息限流（额外保险）
    const now = Date.now();
    const bucket = this.matchBuckets.get(taskId) || { tokens: 0, lastRefill: now };
    const elapsed = now - bucket.lastRefill;
    bucket.tokens = Math.min(MAX_MATCH_BURST, bucket.tokens + (elapsed / 1000) * MAX_MATCH_PER_SEC);
    bucket.lastRefill = now;

    if (bucket.tokens < 1) {
      this.matchBuckets.set(taskId, bucket);
      return;
    }
    bucket.tokens -= 1;
    this.matchBuckets.set(taskId, bucket);

    // 发送匹配消息（只推元数据；完整公钥由前端从 /api/keys 拉取）
    const message: SSEMessage = {
      type: 'match',
      taskId,
      fingerprint: key.fingerprint,
      keyId: key.keyId,
      patternType: matchedRule?.type || 'unknown',
      patternId: msg.patternId,
      matchedText: msg.matchedText,
      color: msg.color,
      attemptsToFind: msg.attempts,
      publicKeyAvailable: true,
      privateKeyAvailable: true,
    };

    this.broadcastSSEMessage(taskId, message);
  }

  async stopTask(taskId: string) {
    console.log(`[TaskManager] 停止任务: taskId=${taskId}`);

    // 通知并终止所有相关 Worker 线程
    const toKill: WorkerInfo[] = [];
    this.workers.forEach((info, key) => {
      if (info.taskId === taskId) {
        toKill.push(info);
        this.workers.delete(key);
      }
    });

    for (const info of toKill) {
      try {
        info.worker.postMessage({ type: 'stop' });
      } catch {
        /* 已退出 */
      }
      // 强制终止（terminate 会立即结束线程，不等待收尾）
      try {
        await info.worker.terminate();
      } catch {
        /* 已退出 */
      }
    }
    if (toKill.length > 0) {
      console.log(`[TaskManager] 已终止 ${toKill.length} 个 Worker 线程: taskId=${taskId}`);
    }

    this.matchBuckets.delete(taskId);
    this.lastDbWrite.delete(taskId);

    // 更新任务状态
    const task = this.tasks.get(taskId);
    if (task) {
      task.status = 'stopped';
      this.tasks.set(taskId, task);
      stopTask(taskId);

      // 发送完成消息
      const message: SSEMessage = {
        type: 'complete',
        taskId,
        totalAttempts: task.totalAttempts,
        totalMatches: task.matchesFound,
      };

      this.broadcastSSEMessage(taskId, message);
    }
  }

  getTask(taskId: string): MiningTask | undefined {
    // 先从内存获取
    const memoryTask = this.tasks.get(taskId);
    if (memoryTask) {
      return memoryTask;
    }

    // 内存中没有，从数据库加载
    const dbTask = getTask(taskId);
    if (dbTask) {
      // 转换日期类型
      const task: MiningTask = {
        ...dbTask,
        startedAt: new Date(dbTask.startedAt),
        stoppedAt: dbTask.stoppedAt ? new Date(dbTask.stoppedAt) : undefined,
      };
      this.tasks.set(taskId, task);
      return task;
    }

    return undefined;
  }

  registerSSEClient(taskId: string, callback: (message: SSEMessage) => void) {
    let clients = this.sseClients.get(taskId);
    if (!clients) {
      clients = new Set();
      this.sseClients.set(taskId, clients);
    }
    clients.add(callback);
    console.log(`[TaskManager] SSE 客户端已注册: taskId=${taskId}, 客户端数=${clients.size}`);
  }

  unregisterSSEClient(taskId: string, callback: (message: SSEMessage) => void) {
    const clients = this.sseClients.get(taskId);
    if (clients) {
      clients.delete(callback);
      console.log(`[TaskManager] SSE 客户端已注销: taskId=${taskId}, 剩余客户端数=${clients.size}`);
      if (clients.size === 0) {
        this.sseClients.delete(taskId);
      }
    }
  }

  private broadcastSSEMessage(taskId: string, message: SSEMessage) {
    const clients = this.sseClients.get(taskId);
    if (clients) {
      clients.forEach(callback => callback(message));
    } else {
      console.warn(`[TaskManager] 广播时找不到 SSE 客户端: taskId=${taskId}, type=${message.type}`);
    }
  }

  private cleanupTasks() {
    const now = Date.now();
    const cutoffTime = now - (24 * 60 * 60 * 1000); // 24小时

    this.tasks.forEach((task, taskId) => {
      if (task.status === 'stopped' && task.startedAt.getTime() < cutoffTime) {
        this.tasks.delete(taskId);
        this.sseClients.delete(taskId);
      }
    });
  }
}

// 导出单例
//
// 注意：Next.js 会把服务端模块分别打进各个 route bundle，
// 同一个文件可能被实例化多次（start 路由一份、stream 路由一份、keys 路由一份）。
// 这样会得到多个 TaskManager：worker 跑在 A，SSE 客户端注册在 B，
// 结果就是「只收到初始快照、后面再也没有推送」。
// 用 globalThis 保存实例，保证整个 Node 进程共用一个。
const globalForTaskManager = globalThis as unknown as { __pgpTaskManager?: TaskManager };

export const taskManager =
  globalForTaskManager.__pgpTaskManager ?? new TaskManager();

if (!globalForTaskManager.__pgpTaskManager) {
  globalForTaskManager.__pgpTaskManager = taskManager;
}
