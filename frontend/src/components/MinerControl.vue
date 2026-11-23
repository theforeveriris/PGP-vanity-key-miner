<template>
  <div class="miner-control">
    <!-- 状态 + 配置 -->
    <div class="control-header">
      <div class="status-badge" :class="{ running: isRunning }">
        <span class="status-dot"></span>
        {{ isRunning ? '运行中' : '已停止' }}
      </div>
      <button @click="showConfig" class="ghost-btn config-btn" title="配置">
        <Settings class="icon-sm" :size="14" />
      </button>
    </div>

    <!-- 规则配置摘要 -->
    <div class="config-summary">
      <div class="summary-item">
        <span class="summary-label">独立规则</span>
        <span class="summary-value">{{ enabledIndependentRulesCount }} / {{ ruleEngineStore.independentRules.length }}</span>
      </div>
      <div class="summary-item">
        <span class="summary-label">规则组</span>
        <span class="summary-value">{{ enabledRuleGroupsCount }} / {{ ruleEngineStore.ruleGroups.length }}</span>
      </div>
      <div class="summary-item">
        <span class="summary-label">冲突策略</span>
        <span class="summary-value">{{ conflictStrategyLabel }}</span>
      </div>
      <div class="summary-item">
        <span class="summary-label">逻辑关系</span>
        <span class="summary-value">{{ logicOperatorLabel }}</span>
      </div>
    </div>

    <!-- 线程数 + 控制按钮 -->
    <div class="control-row">
      <label class="threads-label" title="Worker 线程数">
        <Cpu class="icon-sm" :size="13" />
        <input
          type="number"
          v-model.number="threads"
          min="1"
          max="32"
          class="line-input threads-input"
        />
      </label>
      <div class="logic-toggle" role="group" aria-label="规则组合逻辑">
        <button
          class="pill-tab"
          :class="{ active: logicOperator === 'OR' }"
          @click="logicOperator = 'OR'"
          title="任一规则命中即算命中"
        >
          OR
        </button>
        <button
          class="pill-tab"
          :class="{ active: logicOperator === 'AND' }"
          @click="logicOperator = 'AND'"
          title="所有规则都命中才算命中"
        >
          AND
        </button>
      </div>
      <div class="logic-toggle" role="group" aria-label="挖掘引擎">
        <button
          class="pill-tab"
          :class="{ active: engine === 'cpu' }"
          @click="engine = 'cpu'"
          title="CPU 多线程挖掘"
        >
          CPU
        </button>
        <button
          class="pill-tab"
          :class="{ active: engine === 'gpu' }"
          @click="engine = 'gpu'"
          title="GPU 挖掘(CUDA)——规则不受支持时自动回落 CPU"
        >
          GPU
        </button>
      </div>
      <button
        @click="startMining"
        :disabled="isRunning || !hasEnabledRules"
        class="ghost-btn icon-btn start-btn"
        title="开始挖掘"
      >
        <Play class="icon-sm" :size="14" />
      </button>
      <button
        @click="stopMining"
        :disabled="!isRunning"
        class="ghost-btn icon-btn stop-btn"
        title="停止挖掘"
      >
        <Square class="icon-sm" :size="14" />
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, inject } from 'vue'
import { Settings, Cpu, Play, Square } from 'lucide-vue-next'
import { useMinerStore } from '../stores/miner'
import { useRuleEngineStore } from '../stores/ruleEngine'

const minerStore = useMinerStore()
const ruleEngineStore = useRuleEngineStore()
// 通过 computed 保持响应性：直接解构 store 的 ref 会丢失响应式更新
const isRunning = computed(() => minerStore.isRunning)

// 注入配置按钮显示函数
const showConfig = inject<() => void>('showConfig', () => {
  console.warn('showConfig not provided')
})

const threads = ref(4)

// 独立规则之间的组合逻辑
const logicOperator = ref<'AND' | 'OR'>('OR')

// 挖掘引擎: cpu | gpu(CUDA)
const engine = ref<'cpu' | 'gpu'>('cpu')

// 计算启用的独立规则数量
const enabledIndependentRulesCount = computed(() => {
  return ruleEngineStore.independentRules.filter(r => r.enabled).length
})

// 计算启用的规则组数量
const enabledRuleGroupsCount = computed(() => {
  return ruleEngineStore.ruleGroups.filter(g => g.enabled).length
})

// 冲突策略显示标签
const conflictStrategyLabel = computed(() => {
  const strategyMap: Record<string, string> = {
    'priority': '按优先级',
    'first-match': '首个匹配',
    'all': '全部执行',
    'group-first': '规则组优先'
  }
  return strategyMap[ruleEngineStore.conflictResolution] || '按优先级'
})

// 逻辑关系显示标签
const logicOperatorLabel = computed(() => {
  // 如果有规则组，显示混合
  if (ruleEngineStore.ruleGroups.length > 0) {
    return '混合（见规则引擎）'
  }
  // 否则显示独立规则的当前逻辑
  return logicOperator.value === 'AND' ? '与 (AND)' : '或 (OR)'
})

// 是否有启用的规则
const hasEnabledRules = computed(() => {
  const hasIndependentRules = ruleEngineStore.independentRules.some(r => r.enabled)
  const hasGroupRules = ruleEngineStore.ruleGroups.some(g => g.enabled && g.ruleRefs.some(ref => ref.enabled))
  return hasIndependentRules || hasGroupRules
})

function startMining() {
  const enabledRules = ruleEngineStore.independentRules.filter(rule => rule.enabled)
  const enabledGroups = ruleEngineStore.ruleGroups.filter(g => g.enabled)

  if (enabledRules.length === 0 && enabledGroups.length === 0) {
    alert('请至少启用一条规则或创建一个规则组')
    return
  }

  // 构建规则配置
  const ruleConfig = ruleEngineStore.exportConfiguration()

  minerStore.startMining({
    patterns: enabledRules,
    threads: threads.value,
    logicOperator: logicOperator.value,
    groups: enabledGroups,
    ruleConfig: ruleConfig,
    engine: engine.value,
  })
}

function stopMining() {
  minerStore.stopMining()
}
</script>

<style scoped>
.miner-control {
  background: transparent;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.control-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  background: var(--bg-raised);
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
  color: var(--fg-muted);
  transition: all 0.3s ease;
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}

.status-badge.running {
  background: rgba(16, 185, 129, 0.15);
  color: var(--green);
}

.status-badge.running .status-dot {
  animation: pulse 1.4s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.25; }
}

.config-btn {
  padding: 4px 7px;
  line-height: 0;
  border-color: transparent;
  color: var(--accent);
}

.icon-sm {
  display: block;
  flex-shrink: 0;
}

.config-summary {
  display: flex;
  flex-direction: column;
  gap: 2px;
  border-radius: 6px;
  overflow: hidden;
  background: var(--bg-raised);
}

.summary-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  padding: 3px 8px;
  font-size: 12px;
}

.summary-item:nth-child(odd) {
  background: rgba(255, 255, 255, 0.03);
}

.summary-label {
  color: var(--fg-muted);
  white-space: nowrap;
}

.summary-value {
  font-family: 'Courier New', monospace;
  font-weight: 700;
  color: var(--fg);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.control-row {
  display: flex;
  align-items: center;
  gap: 5px;
}

.threads-label {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 12px;
  color: var(--fg-muted);
  white-space: nowrap;
}

.threads-input {
  width: 40px;
  padding: 3px 4px;
  font-size: 12px;
  text-align: center;
}

/* OR / AND 分段切换 */
.logic-toggle {
  display: inline-flex;
  gap: 2px;
  padding: 1px;
  border-radius: 12px;
  background: rgba(0, 0, 0, 0.3);
}

.pill-tab {
  padding: 2px 8px;
  border-radius: 10px;
  border: none;
  background: transparent;
  color: var(--fg-muted);
  font-size: 10px;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all 0.15s ease;
}

.pill-tab.active {
  background: var(--accent);
  color: #ffffff;
}

/* 仅图标的按钮 */
.icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px;
  min-width: 26px;
  height: 26px;
  line-height: 0;
}

.line-input {
  border: 1px solid #333333;
  border-radius: 4px;
  background: var(--bg-raised);
  color: var(--fg);
  font-family: inherit;
}

.ghost-btn {
  background: transparent;
  border: 1px solid #3a3a3a;
  border-radius: 5px;
  padding: 6px 12px;
  color: var(--fg-muted);
  cursor: pointer;
  font-family: inherit;
  transition: all 0.15s ease;
}

.ghost-btn:hover:not(:disabled) {
  border-color: var(--accent);
  color: var(--accent);
}

.ghost-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.start-btn {
  border-color: var(--green);
  color: var(--green);
}

.stop-btn {
  border-color: var(--red);
  color: var(--red);
}

.start-btn:hover:not(:disabled) {
  background: rgba(16, 185, 129, 0.12);
  border-color: var(--green);
  color: var(--green);
}

.stop-btn:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.12);
  border-color: var(--red);
  color: var(--red);
}
</style>
