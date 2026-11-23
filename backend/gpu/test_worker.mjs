// 隔离测试 gpu.worker.mjs 的消息流(不经后端)
import { Worker } from 'node:worker_threads';
import path from 'node:path';

const w = new Worker(path.join(process.cwd(), 'app', 'workers', 'gpu.worker.mjs'), {
  workerData: {
    patterns: [{ id: 'iso1', type: 'consecutive', params: { minLength: 5 }, color: '#00f0ff', enabled: true, name: 't' }],
    logicOperator: 'OR',
    groups: [],
  },
});

const counts = {};
w.on('message', (m) => {
  counts[m.type] = (counts[m.type] || 0) + 1;
  if (m.type === 'match' && counts.match <= 2) console.log('MATCH:', m.keyId, JSON.stringify(m.matchedText));
  if (m.type === 'error' && counts.error <= 3) console.log('ERROR:', String(m.message).slice(0, 200));
  if (m.type === 'gpu_unsupported') console.log('UNSUPPORTED:', m.message);
});
w.on('error', (e) => console.log('WORKER FATAL:', e.message));
w.on('exit', (c) => { console.log('message counts:', JSON.stringify(counts), 'exit', c); process.exit(0); });

setTimeout(() => {
  w.postMessage({ type: 'stop' });
  setTimeout(() => w.terminate(), 2000);
}, 12000);
