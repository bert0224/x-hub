import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import vm from 'node:vm'
import test from 'node:test'
import ts from 'typescript'

const require = createRequire(import.meta.url)
const root = path.resolve(import.meta.dirname, '..')
const flush = () => new Promise((resolve) => setImmediate(resolve))

// 在真实模块的公开入口验证行为，仅替换桌面 IPC、时钟与 DOM 边界。
function loadModule(file, replacements, globals = {}, cache = new Map()) {
  const absolute = path.resolve(root, file)
  if (cache.has(absolute)) return cache.get(absolute).exports
  const module = { exports: {} }
  cache.set(absolute, module)
  const output = ts.transpileModule(readFileSync(absolute, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText
  const localRequire = (name) => {
    if (name in replacements) return replacements[name]
    if (name.startsWith('.')) {
      const target = path.resolve(path.dirname(absolute), name)
      return loadModule(`${target}.ts`, replacements, globals, cache)
    }
    return require(name)
  }
  vm.runInNewContext(output, { module, exports: module.exports, require: localRequire,
    console, URL, setTimeout, clearTimeout, setInterval, clearInterval, ...globals }, { filename: absolute })
  return module.exports
}

test('关闭联网后重新启动监听，不得发起请求或注册定时器', async () => {
  let probes = 0
  let timers = 0
  const { useStore } = loadModule('src/stores/workbench.ts', {
    '../api/tauri': { isTauri: () => true, tauriApi: {
      saveConfig: async () => {}, checkConnectivity: async () => { probes++; return true },
    } },
  }, { setInterval: () => { timers++; return 1 }, clearInterval: () => {} })
  const store = useStore()
  await store.setOnlineEnabled(false)
  store.startOnlineMonitor()
  await flush()
  assert.equal(probes, 0)
  assert.equal(timers, 0)
})

function bridgeFixture() {
  const mounted = []
  const listeners = new Map()
  const calls = []
  const replies = []
  const origin = 'http://xhub-ext.e-0123456789abcdef.localhost'
  const frame = { src: '', addEventListener() {}, removeEventListener() {},
    contentWindow: { postMessage: (...args) => replies.push(args) } }
  const { useExtensionFrame } = loadModule('src/composables/useExtensionFrame.ts', {
    vue: { ref: (value) => ({ value }), watch() {}, onMounted: (fn) => mounted.push(fn), onBeforeUnmount() {} },
    '../api/tauri': { isTauri: () => true, tauriApi: {
      readExtensionEntry: async () => `${origin}/demo/index.html`,
      xhubCall: async (...args) => { calls.push(args); return [] },
    } },
    './themeTokens': { registerExtensionFrame() {}, unregisterExtensionFrame() {},
      collectThemeTokens: () => ({}), broadcastExtensionEvent() {}, routeExtensionCall() {}, routeExtensionCallResult() {} },
  }, {
    window: { addEventListener: (name, fn) => listeners.set(name, fn), setTimeout: () => 1, setInterval: () => 2 },
    document: { visibilityState: 'visible', addEventListener() {} }, clearTimeout() {},
  })
  const instance = useExtensionFrame(() => 'demo', () => 'view')
  instance.frameRef.value = frame
  mounted.forEach((fn) => fn())
  return { frame, origin, calls, replies, listeners }
}

test('扩展导航至外部来源后不能沿用桥权限', async () => {
  const f = bridgeFixture()
  await flush()
  f.listeners.get('message')({ source: f.frame.contentWindow, origin: 'https://untrusted.invalid',
    data: { __xhub: true, type: 'call', id: 1, namespace: 'data', method: 'notes.list' } })
  await flush()
  assert.equal(f.calls.length, 0)
})

test('原扩展来源仍能调用桥，回复必须绑定到原来源', async () => {
  const f = bridgeFixture()
  await flush()
  f.listeners.get('message')({ source: f.frame.contentWindow, origin: f.origin,
    data: { __xhub: true, type: 'call', id: 1, namespace: 'data', method: 'notes.list' } })
  await flush()
  assert.equal(f.calls.length, 1)
  assert.equal(f.replies.at(-1)[1], f.origin)
})

test('并发跨扩展调用使用独立编号，其他扩展不能伪造回复', () => {
  const routing = loadModule('src/composables/themeTokens.ts', {})
  const frame = () => ({ contentWindow: { postMessage: (...args) => messages.push(args) } })
  const messages = []
  const a = frame(), b = frame(), target = frame(), attacker = frame()
  for (const [f, id] of [[a, 'a'], [b, 'b'], [target, 'target'], [attacker, 'attacker']]) {
    routing.registerExtensionFrame(f, id, `http://xhub-ext.${id}.localhost`)
  }
  routing.routeExtensionCall(a, 1, 'target', 'query', {})
  routing.routeExtensionCall(b, 1, 'target', 'query', {})
  const ids = messages.map(([message]) => message.id)
  assert.notEqual(ids[0], ids[1])
  messages.length = 0
  routing.routeExtensionCallResult(attacker, ids[0], true, '伪造', null)
  assert.equal(messages.length, 0)
  routing.routeExtensionCallResult(target, ids[0], true, '结果 A', null)
  routing.routeExtensionCallResult(target, ids[1], true, '结果 B', null)
  assert.equal(messages[0][0].data, '结果 A')
  assert.equal(messages[0][1], 'http://xhub-ext.a.localhost')
  assert.equal(messages[1][1], 'http://xhub-ext.b.localhost')
})
