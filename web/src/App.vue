<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'

const menus = [
  { id: 'generate', icon: '✦', name: '生成证书', sub: '创建测试身份' },
  { id: 'bundles', icon: '▣', name: '证书与签名', sub: '管理产物与文件签名' },
  { id: 'services', icon: '◎', name: 'TLS 测试服务', sub: '启动、观察与停止' },
  { id: 'catalog', icon: '◇', name: 'CA 证书清单', sub: '检查身份与信任链' },
  { id: 'guide', icon: '≡', name: '使用指南', sub: '参数、命令与结果判读' },
]
const page = ref('generate')
const activeMenu = computed(() => menus.find(m => m.id === page.value))
const entries = ref([]), bundles = ref([]), services = ref([]), tools = ref({}), directory = ref('')
const busy = ref(''), error = ref(''), locked = ref(true), loginToken = ref('')
const token = ref('')
const connected = ref(false)
let networkError = ''
const detail = ref(null), detailTab = ref('overview'), files = ref([]), serviceDialog = ref(false), logDialog = ref(false), serviceLogs = ref('')
const filter = reactive({ query: '', usage: '', chain: '' })
const generate = reactive({ type: 'tls', domain: '*.demo.com,demo.com', ip: '', ca: '', chain: 'ecc', subject: 'FakeCA Internal Trust Test', organization: 'Internal Security Test', valid_for: '8760h', out: '', password_env: '', input: '', output: '', tool: '' })
const signing = reactive({ type: 'software', bundle_id: '', input: '', output: '', tool: '', password_env: '' })
const serviceForm = reactive({ bundle_id: '', listen: '127.0.0.1:8443' })
const signLogs = ref(''), importPath = ref(''), advanced = ref([]), simultaneous = ref(false)
const compatibleCAs = computed(() => entries.value.filter(e => e.chain === generate.chain && e.usage === (generate.type === 'tls' ? 'tls' : 'codesign')))
const codeBundles = computed(() => bundles.value.filter(b => b.report.type !== 'tls'))
const tlsBundles = computed(() => bundles.value.filter(b => b.report.type === 'tls'))
const filteredEntries = computed(() => entries.value.filter(e => (!filter.usage || e.usage === filter.usage) && (!filter.chain || e.chain === filter.chain) && (!filter.query || `${e.name} ${e.id} ${e.sha256}`.toLowerCase().includes(filter.query.toLowerCase()))))
const selectedCA = computed(() => compatibleCAs.value.find(e => e.id === generate.ca))
const typeName = value => ({ tls: 'TLS 域名 / IP', software: '软件签名', jar: 'JAR 签名', codesign: '代码签名' }[value] || value)
const reportIdentity = report => [...(report.domains || []), ...(report.ips || [])].join(', ') || (report.type === 'tls' ? '未记录域名或 IP' : typeName(report.type))
const reportTypeName = report => {
  if (report.type !== 'tls') return typeName(report.type)
  if (report.domains?.length && report.ips?.length) return 'TLS 域名 + IP'
  if (report.ips?.length) return 'TLS IP'
  return report.domains?.length ? 'TLS 域名' : 'TLS 证书'
}
const chainName = value => ({ ecc: '经 emSign ECC G3 根', native: 'emSign TLS/CS 自签名根', aaa: 'Sectigo AAA 交叉签名' }[value] || value)
const time = value => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
const size = value => value > 1048576 ? `${(value / 1048576).toFixed(1)} MiB` : `${(value / 1024).toFixed(1)} KiB`
const quote = text => `'${String(text).replaceAll("'", "''")}'`
const command = computed(() => {
  let result = `fakeca generate --type ${generate.type}`
  if (generate.type === 'tls') { if (generate.domain) result += ` --domain ${quote(generate.domain)}`; if (generate.ip) result += ` --ip ${quote(generate.ip)}` }
  if (generate.ca) result += ` --ca ${generate.ca}`
  result += ` --chain ${generate.chain} --valid-for ${quote(generate.valid_for)}`
  result += ` --subject ${quote(generate.subject)}`
  result += ` --organization ${quote(generate.organization)}`
  if (generate.out) result += ` --out ${quote(generate.out)}`
  if (generate.password_env && generate.type !== 'tls') result += ` --password-env ${quote(generate.password_env)}`
  if (simultaneous.value && generate.type !== 'tls') for (const key of ['input', 'output', 'tool']) if (generate[key]) result += ` --${key} ${quote(generate[key])}`
  return result
})

watch(() => [generate.type, generate.chain], () => { if (!compatibleCAs.value.some(e => e.id === generate.ca)) generate.ca = '' })
watch(() => signing.bundle_id, id => { const b = bundles.value.find(b => b.id === id); if (b) signing.type = b.report.type === 'jar' ? 'jar' : 'software' })

async function api(path, options = {}) {
  const headers = { 'X-FakeCA-Token': token.value, ...options.headers }
  if (options.body && !(options.body instanceof FormData)) { headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(options.body) }
  let response; try { response = await fetch(`/api${path}`, { ...options, headers }); connected.value = response.status !== 401; if (networkError && error.value === networkError) error.value = ''; networkError = '' } catch { connected.value = false; networkError = '无法连接管理服务，请确认 fakeca web 仍在运行，并使用终端提供的地址重新打开。'; throw new Error(networkError) }
  if (options.binary && response.ok) { const mime = response.headers.get('Content-Type') || ''; if (!mime.includes('application/zip') && !mime.includes('application/octet-stream')) throw new Error('下载响应格式不正确，请检查管理服务地址或代理配置。'); return response.blob() }
  let data; try { data = await response.json() } catch { throw new Error(`管理服务返回了无法解析的数据（HTTP ${response.status}），请检查地址与代理配置。`) }
  if (!response.ok) { if (response.status === 401) locked.value = true; const err = new Error(data.error || '操作失败'); err.details = data; throw err }
  return data
}
async function refresh() {
  const data = await api('/state'); bundles.value = data.bundles; services.value = data.services
  if (detail.value) detail.value = bundles.value.find(b => b.id === detail.value.id) || detail.value
}
async function connect() {
  busy.value = 'connect'; error.value = ''
  try {
    if (loginToken.value) { const input = loginToken.value.trim(); if (input.includes('#')) { try { const parsed = new URL(input); const supplied = new URLSearchParams(parsed.hash.slice(1)).get('token'); if (!supplied) throw new Error(); token.value = supplied } catch { throw new Error('完整地址格式无效，请粘贴终端中包含 #token= 的完整地址，或只填写访问令牌。') } } else { token.value = input } }
    const [data, state] = await Promise.all([api('/bootstrap'), api('/state')])
    entries.value = data.entries; tools.value = data.tools; directory.value = data.directory; bundles.value = state.bundles; services.value = state.services
    locked.value = false
    try { sessionStorage.setItem('fakeca-token', token.value) } catch {}
  } catch (err) { error.value = err.message } finally { busy.value = '' }
}
async function act(name, task) { if (busy.value) { ElMessage.info('另一个操作正在进行，请稍后再试'); return }; busy.value = name; error.value = ''; try { await task() } catch (err) { error.value = err.message; if (err.details && 'logs' in err.details) signLogs.value = err.details.logs; ElMessage.error(err.message) } finally { busy.value = '' } }
async function submitGenerate() {
  if (generate.type === 'tls' && !generate.domain.trim() && !generate.ip.trim()) { error.value = '请至少填写一个域名或 IP 地址。'; return }
  await act('generate', async () => {
    const payload = { ...generate }; signLogs.value = ''; if (payload.type === 'tls') payload.password_env = ''
    if (generate.type !== 'tls') { payload.domain = ''; payload.ip = '' }
    if (!simultaneous.value || generate.type === 'tls') { payload.input = ''; payload.output = ''; payload.tool = '' }
    try { const result = await api('/generate', { method: 'POST', body: payload }); await refresh(); await showDetail(result); ElMessage.success(payload.input ? '证书包与签名文件已生成' : '证书包已生成') }
    catch (err) { if (err.details?.bundle) { await refresh(); await showDetail(bundles.value.find(b => b.id === err.details.bundle.id) || err.details.bundle); detailTab.value = 'logs' }; throw err }
  })
}
async function showDetail(bundle) { const list = await api(`/files/${bundle.id}`); detail.value = bundle; detailTab.value = 'overview'; files.value = list }
async function upload(event, target) {
  const file = event.target.files?.[0]; if (!file) return
  await act('upload', async () => { const data = new FormData(); data.append('file', file); const result = await api('/upload', { method: 'POST', body: data }); target.input = result.path; ElMessage.success('原始文件已上传，可开始签名') }); event.target.value = ''
}
async function submitSign() {
  if (!signing.bundle_id || !signing.input || !signing.output) { error.value = '请先选择代码签名证书包，并填写原始文件和签名输出路径。'; return }
  await act('sign', async () => { signLogs.value = ''; const result = await api('/sign', { method: 'POST', body: { ...signing } }); signLogs.value = result.logs; await refresh(); ElMessage.success('签名文件已生成') })
}
async function importBundle() { if (!importPath.value.trim()) { error.value = '请填写已有证书包在服务器上的目录。'; return }; await act('import', async () => { await api('/import', { method: 'POST', body: { path: importPath.value } }); importPath.value = ''; await refresh(); ElMessage.success('已有证书包已导入') }) }
function useForSign(bundle) { signing.bundle_id = bundle.id; page.value = 'bundles'; detail.value = null }
function useForService(bundle) { serviceForm.bundle_id = bundle?.id || tlsBundles.value[0]?.id || ''; serviceDialog.value = true; detail.value = null }
async function startService() { await act('start', async () => { await api('/services', { method: 'POST', body: { ...serviceForm } }); serviceDialog.value = false; page.value = 'services'; await refresh(); ElMessage.success('TLS 测试服务已启动') }) }
async function stopService(id) { await act('stop', async () => { await api(`/services/${id}`, { method: 'DELETE' }); await refresh(); ElMessage.success('测试服务已停止') }) }
async function download(bundle, name = '') { await act('download', async () => { const blob = await api(name ? `/download/${bundle.id}/${encodeURIComponent(name)}` : `/archive/${bundle.id}`, { binary: true }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name || `fakeca-${bundle.report.ca.id}.zip`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000) }) }
async function copy(value) { try { await navigator.clipboard.writeText(value); ElMessage.success('已复制') } catch { ElMessage.warning('浏览器不允许复制，请手动选中文本') } }
function chooseCA(row) { generate.type = row.usage === 'tls' ? 'tls' : 'software'; generate.chain = row.chain; generate.ca = row.id; page.value = 'generate' }
let timer
onMounted(() => {
  const fragment = new URLSearchParams(location.hash.slice(1)).get('token')
  try { token.value = fragment || sessionStorage.getItem('fakeca-token') || '' } catch { token.value = fragment || '' }
  if (fragment) history.replaceState(null, '', location.pathname + location.search)
  if (token.value) connect()
  timer = setInterval(() => { if (!locked.value && !busy.value) refresh().catch(err => { error.value = err.message }) }, 5000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div v-if="locked" class="connect-screen">
    <div class="connect-card">
      <div class="brand-mark large">F<span>✓</span></div><p class="eyebrow">FAKECA / TRUST LAB</p>
      <h1>连接信任验证工作台</h1><p class="muted">粘贴终端显示的访问令牌或完整地址。令牌在每次启动时更新。</p>
      <el-input v-model="loginToken" type="password" show-password placeholder="访问令牌或 http://…/#token=…" aria-label="访问令牌" @keyup.enter="connect" />
      <el-button type="primary" size="large" :loading="busy === 'connect'" @click="connect">进入工作台 →</el-button>
      <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
      <p class="small muted">本机工具 · 独立会话 · 无外部 CDN</p>
    </div>
  </div>
  <div v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand"><div class="brand-mark">F<span>✓</span></div><div><strong>FakeCA</strong><small>TRUST VERIFICATION LAB</small></div></div>
      <div class="nav-caption">验证工作台</div>
      <nav aria-label="主导航"><button v-for="menu in menus" :key="menu.id" :class="{ active: page === menu.id }" @click="page = menu.id"><span class="nav-icon">{{ menu.icon }}</span><span><b>{{ menu.name }}</b><small>{{ menu.sub }}</small></span><span v-if="menu.id === 'services' && services.length" class="nav-count">{{ services.length }}</span></button></nav>
      <div class="sidebar-bottom"><span class="status-dot" :class="{ offline: !connected }"></span> {{ connected ? '已连接管理服务' : '管理服务连接中断' }}<small>Vue 3 · Element Plus · Go</small></div>
    </aside>
    <main class="main">
      <header class="topbar"><div><span class="muted">工作台</span><span class="slash">/</span><strong>{{ activeMenu.name }}</strong></div><div class="top-status"><span class="status-dot" :class="{ offline: !connected }"></span> {{ connected ? '内网信任验证' : '管理服务已断开' }} <el-tag size="small" type="info" effect="plain">会话已认证</el-tag></div></header>
      <div class="content">
        <div class="page-heading"><div><p class="eyebrow">TRUST, VERIFIED.</p><h1>{{ activeMenu.name }}</h1><p class="muted">{{ { generate: '配置一次测试身份，检查设备真正接受的证书链。', bundles: '管理生成结果，使用同一套身份完成软件与 JAR 签名。', services: '为每条证书链提供独立端点，观察实际客户端的验证行为。', catalog: '从真实证书出发，查看用途、信任路径与 SHA-256 指纹。', guide: '从参数配置到结果判读，每一步都有明确依据。' }[page] }}</p></div><el-button @click="act('refresh', refresh)" :loading="busy === 'refresh'">↻ 刷新状态</el-button></div>
        <el-alert v-if="error" class="page-error" :title="error" type="error" show-icon @close="error = ''" />

        <template v-if="page === 'generate'">
          <div class="stats-row"><div><span>涉事 CA 证书</span><strong>16 <small>张</small></strong></div><div><span>可验证链路</span><strong>{{ entries.length }} <small>种组合</small></strong></div><div><span>默认有效期</span><strong>365 <small>天</small></strong></div><div><span>运行中端点</span><strong>{{ services.length }} <small>个</small></strong></div></div>
          <div class="workspace-grid">
            <section class="panel form-panel"><div class="panel-heading"><div><h2>创建测试证书</h2><p>身份、用途与信任路径，按实际测试场景配置。</p></div><span class="step-pill">01 / CONFIGURE</span></div>
              <el-form label-position="top" @submit.prevent="submitGenerate">
                <div class="type-cards"><button v-for="item in [{ id: 'tls', icon: '🌐', name: 'TLS 证书', text: '域名 / IP / 泛域名' }, { id: 'software', icon: '📦', name: '软件签名', text: 'EXE / DLL / MSI 等' }, { id: 'jar', icon: '☕', name: 'JAR 签名', text: 'Java 归档文件' }]" :key="item.id" type="button" :class="{ selected: generate.type === item.id }" @click="generate.type = item.id"><span>{{ item.icon }}</span><b>{{ item.name }}</b><small>{{ item.text }}</small></button></div>
                <div v-if="generate.type === 'tls'" class="field-section"><div class="section-label">🌐 证书身份</div><el-form-item label="域名 · DNS SAN"><el-input v-model="generate.domain" placeholder="*.demo.com,demo.com,api.example.internal" /><div class="field-hint">多个域名用逗号分隔。*.demo.com 不包含 demo.com，需分别填写。</div></el-form-item><el-form-item label="IP 地址 · 可选"><el-input v-model="generate.ip" placeholder="192.168.10.20,127.0.0.1" /><div class="field-hint">域名与 IP 可同时填写；此处不配置 DNS 或监听地址。</div></el-form-item></div>
                <div class="field-section"><div class="section-label">🔗 CA 与信任路径</div><div class="form-columns"><el-form-item label="证书链路"><el-select v-model="generate.chain"><el-option label="ecc · 经 ECC G3 根" value="ecc" /><el-option label="native · emSign 自签名根" value="native" /><el-option label="aaa · Sectigo 交叉签名" value="aaa" /></el-select></el-form-item><el-form-item label="签发 CA"><el-select v-model="generate.ca" :placeholder="`随机选择 · ${compatibleCAs.length} 个匹配身份`"><el-option :label="`随机选择 · ${compatibleCAs.length} 个匹配身份`" value="" /><el-option v-for="ca in compatibleCAs" :key="ca.id" :label="ca.id" :value="ca.id" /></el-select></el-form-item></div><div class="form-columns"><el-form-item label="申请有效期"><el-input v-model="generate.valid_for" placeholder="例如 8760h、24h、30m" /><div class="field-hint">h 表示小时，m 表示分钟；8760h = 365 天。实际到期时间不会超过父证书链的到期时间。</div></el-form-item><el-form-item label="输出目录 · 可选"><el-input v-model="generate.out" placeholder="留空自动创建新目录" /><div class="field-hint">服务器本地路径，拒绝覆盖现有目录。</div></el-form-item></div></div>
                <el-collapse v-model="advanced" class="advanced"><el-collapse-item title="⚙️ 身份名称与高级参数" name="identity"><div class="form-columns"><el-form-item label="证书名称 / 测试发布者"><el-input v-model="generate.subject" /></el-form-item><el-form-item label="组织名称"><el-input v-model="generate.organization" /></el-form-item></div><el-form-item v-if="generate.type !== 'tls'" label="PKCS#12 密码环境变量名 · 可选"><el-input v-model="generate.password_env" placeholder="例如 FAKECA_P12_PASSWORD" /><div class="field-hint">变量需在启动 Web 服务前设置；留空则生成 password.txt。</div></el-form-item></el-collapse-item></el-collapse>
                <div v-if="generate.type !== 'tls'" class="inline-sign"><div class="sign-toggle"><el-switch v-model="simultaneous" aria-label="生成证书后同时签名文件" /><span>生成证书后同时签名文件</span></div><template v-if="simultaneous"><el-form-item label="原始文件路径"><div class="input-with-action"><el-input v-model="generate.input" placeholder="服务器本地文件路径，或上传文件" /><label class="upload-button">上传文件<input type="file" @change="upload($event, generate)" /></label></div></el-form-item><div class="form-columns"><el-form-item label="签名输出路径"><el-input v-model="generate.output" placeholder="例如 out/hello-signed.exe" /></el-form-item><el-form-item label="签名工具路径 · 可选"><el-input v-model="generate.tool" :placeholder="generate.type === 'jar' ? 'jarsigner 路径；默认查找 PATH' : 'osslsigncode 路径；默认查找 PATH'" /></el-form-item></div></template></div>
                <div class="form-footer"><span>📋 生成结果会记录 CA、指纹及实际有效期。</span><el-button type="primary" size="large" native-type="submit" :loading="busy === 'generate'" :disabled="!!busy && busy !== 'generate'">生成测试证书 →</el-button></div>
              </el-form>
            </section>
            <aside class="summary-column"><section class="panel summary-panel"><span class="eyebrow">TEST PROFILE</span><h2>本次配置</h2><dl><dt>证书用途</dt><dd>{{ typeName(generate.type) }}</dd><dt>信任路径</dt><dd>{{ chainName(generate.chain) }}</dd><dt>CA 身份</dt><dd class="mono">{{ selectedCA?.id || '随机 · 生成后记录实际身份' }}</dd><dt>请求有效期</dt><dd class="mono">{{ generate.valid_for || '未填写' }}</dd></dl><div class="note-box"><template v-if="generate.type === 'tls'"><b>💡 一张证书，多个身份</b><p>域名、泛域名和 IP 均可写入同一张 TLS 证书；服务访问地址应与其中一项匹配。</p></template><template v-else><b>💡 证书身份与文件签名</b><p>证书用于标识测试发布者，签名工具负责计算文件摘要，并生成完整的软件或 JAR 签名。</p></template></div></section><section class="command-panel"><div><b>⌘ 对应 CLI 命令</b><button @click="copy(command)">复制</button></div><code>{{ command }}</code><p>网页默认目录位于 Web 工作目录；CLI 省略 --out 时使用 out/时间戳。</p></section><section class="test-note"><span>⚠️</span><div><template v-if="generate.type === 'tls'"><b>拒绝连接 ≠ 吊销检查生效</b><p>域名、CT、用途或根信任问题也会导致失败。请保留具体错误，并设置正向对照端点。</p></template><template v-else><b>签名完成 ≠ 信任验证通过</b><p>请在目标设备的实际安装器、加载器或执行策略中检查签名信任与吊销结果。</p></template></div></section></aside>
          </div>
        </template>

        <template v-if="page === 'bundles'">
          <section class="panel"><div class="panel-heading"><div><h2>📁 证书包与生成产物 <el-tag size="small" type="info">{{ bundles.length }}</el-tag></h2><p>生成结果保存在服务器上，重启工作台后仍可查看。</p></div><el-button type="primary" plain @click="page = 'generate'">＋ 创建证书包</el-button></div><div class="import-row"><el-input v-model="importPath" placeholder="导入已有 CLI 证书包：填写服务器上的目录，例如 out/tls-test" @keyup.enter="importBundle" /><el-button :loading="busy === 'import'" @click="importBundle">导入目录</el-button></div><el-table :data="bundles" empty-text="尚无证书包。先生成一个，或导入已有目录。"><el-table-column label="测试身份" min-width="220"><template #default="{ row }"><b class="mono">{{ row.report.ca.id }}</b><small class="cell-sub">{{ reportIdentity(row.report) }}</small></template></el-table-column><el-table-column label="类型" min-width="160"><template #default="{ row }"><el-tag :type="row.report.type === 'tls' ? 'success' : 'info'" effect="plain">{{ reportTypeName(row.report) }}</el-tag></template></el-table-column><el-table-column label="链路" width="85"><template #default="{ row }">{{ row.report.ca.chain }}</template></el-table-column><el-table-column label="到期时间" min-width="175"><template #default="{ row }">{{ time(row.report.not_after) }}</template></el-table-column><el-table-column label="操作" width="170" fixed="right"><template #default="{ row }"><el-button link type="primary" @click="act('detail', () => showDetail(row))">查看</el-button><el-button link type="primary" @click="download(row)">下载 ZIP</el-button></template></el-table-column></el-table></section>
          <section class="panel signing-panel"><div class="panel-heading"><div><h2>✍️ 文件签名</h2><p>使用代码签名证书包处理原始文件；不执行被签名程序。</p></div><div class="tool-status"><el-tag v-for="name in ['osslsigncode', 'jarsigner']" :key="name" :type="tools[name]?.available ? 'success' : 'info'" effect="plain">{{ tools[name]?.available ? '✓' : '○' }} {{ name }}</el-tag></div></div><el-form label-position="top" @submit.prevent="submitSign"><div class="form-columns"><el-form-item label="代码签名证书包"><el-select v-model="signing.bundle_id" placeholder="请选择，或先导入已有证书包"><el-option v-for="b in codeBundles" :key="b.id" :label="`${b.report.ca.id} · ${b.report.ca.chain} · ${b.id.slice(0, 6)}`" :value="b.id" /></el-select></el-form-item><el-form-item label="文件类型"><el-select v-model="signing.type"><el-option label="software · Authenticode 软件签名" value="software" /><el-option label="jar · Java 归档签名" value="jar" /></el-select></el-form-item></div><el-form-item label="原始文件"><div class="input-with-action"><el-input v-model="signing.input" placeholder="服务器本地路径，或上传原始文件（最大 64 MiB）" /><label class="upload-button">上传文件<input type="file" @change="upload($event, signing)" /></label></div></el-form-item><div class="form-columns"><el-form-item label="签名输出路径"><el-input v-model="signing.output" placeholder="服务器上的新文件，例如 out/hello-signed.exe" /></el-form-item><el-form-item label="签名工具路径 · 可选"><el-input v-model="signing.tool" placeholder="留空从 PATH 查找；也可指定完整路径" /></el-form-item></div><el-form-item label="PKCS#12 密码环境变量名 · 可选"><el-input v-model="signing.password_env" placeholder="JAR 使用；留空读取证书包 password.txt" /></el-form-item><div class="form-footer"><span>🧩 未加入 PATH 的工具可通过完整路径指定。</span><el-button type="primary" native-type="submit" :loading="busy === 'sign'" :disabled="!!busy && busy !== 'sign'">开始签名 →</el-button></div></el-form><div v-if="signLogs" class="log-panel"><h3>📋 签名工具原始输出</h3><pre>{{ signLogs }}</pre></div></section>
        </template>

        <template v-if="page === 'services'">
          <section class="panel"><div class="panel-heading"><div><h2>🌐 TLS 测试端点</h2><p>管理端与测试端独立监听，可同时启动多个证书链端点。</p></div><el-button type="primary" @click="useForService()">＋ 启动测试服务</el-button></div><div v-if="!services.length" class="empty-state"><span>◎</span><h3>还没有运行中的测试端点</h3><p>选择一个 TLS 证书包，再指定服务器接口和端口。</p><el-button @click="useForService()">配置第一个端点</el-button></div><div v-else class="service-grid"><article v-for="s in services" :key="s.id" class="service-card"><div class="service-top"><el-tag type="success" effect="plain">● 运行中</el-tag><small>{{ time(s.started_at) }}</small></div><h3 class="mono">{{ s.address }}</h3><p>🔗 {{ s.ca }}</p><p class="field-hint">通过证书 SAN 中的域名或 IP 访问此端口。</p><div class="service-actions"><el-button @click="serviceLogs = s.logs || '暂无握手诊断日志。'; logDialog = true">查看诊断</el-button><el-button type="danger" plain :loading="busy === 'stop'" @click="stopService(s.id)">停止服务</el-button></div></article></div></section><div class="guide-grid"><section class="panel mini-guide"><h3>🧭 访问前准备</h3><p>内网设备访问时，用服务器内网 IP 监听，并配置测试域名的 DNS / hosts。端口和网络需可达。</p></section><section class="panel mini-guide"><h3>📋 保留验证依据</h3><p>记录设备和应用版本、证书指纹、实际错误及正向对照结果。测试端点最低支持 TLS 1.2；协议不兼容应单独记录。不要用忽略证书错误的方式验收。</p></section></div>
        </template>

        <template v-if="page === 'catalog'">
          <section class="panel"><div class="panel-heading"><div><h2>◇ 真实 CA 证书目录</h2><p>8 个 CA 身份 · 16 张涉事证书 · 24 种链路组合。点击“使用”带入配置。</p></div><el-button @click="copy(JSON.stringify(entries, null, 2))">复制 JSON</el-button></div><div class="filter-row"><el-input v-model="filter.query" clearable placeholder="搜索 CA 名称、ID 或 SHA-256 指纹" /><el-select v-model="filter.usage" clearable placeholder="全部用途"><el-option label="TLS" value="tls" /><el-option label="代码签名" value="codesign" /></el-select><el-select v-model="filter.chain" clearable placeholder="全部链路"><el-option v-for="v in ['ecc', 'native', 'aaa']" :key="v" :label="v" :value="v" /></el-select></div><el-table :data="filteredEntries" empty-text="没有匹配的 CA，请调整筛选条件。"><el-table-column label="CA 身份" min-width="210"><template #default="{ row }"><b class="mono">{{ row.id }}</b><small class="cell-sub">{{ row.name }}</small></template></el-table-column><el-table-column label="用途 / 链路" width="150"><template #default="{ row }"><el-tag size="small" effect="plain">{{ row.usage === 'tls' ? 'TLS' : '代码签名' }}</el-tag> <span class="mono">{{ row.chain }}</span></template></el-table-column><el-table-column label="CA 证书到期" min-width="160"><template #default="{ row }">{{ time(row.not_after) }}</template></el-table-column><el-table-column label="SHA-256 指纹" min-width="230"><template #default="{ row }"><span class="fingerprint">{{ row.sha256 }}</span></template></el-table-column><el-table-column label="操作" width="80" fixed="right"><template #default="{ row }"><el-button link type="primary" @click="chooseCA(row)">使用 →</el-button></template></el-table-column></el-table></section>
        </template>

        <template v-if="page === 'guide'">
          <div class="guide-grid"><section class="panel mini-guide"><span class="eyebrow">01 / CREATE</span><h2>🌐 多域名与泛域名</h2><p><code>*.demo.com,demo.com</code> 同时覆盖一级子域名和根域名。泛域名不匹配多级子域名；DNS 解析需另外配置。</p><h3>⏱️ 有效期</h3><p>默认 365 天。填写数字与单位：<code>8760h</code> = 365 天，<code>24h</code> = 1 天，<code>30m</code> = 30 分钟。不支持 <code>365d</code>；实际到期时间不会超过父证书链的到期时间。若客户端报告有效期过长，可缩短测试期限后复测。</p></section><section class="panel mini-guide"><span class="eyebrow">02 / VERIFY</span><h2>🔗 选择正确链路</h2><p><b>ecc</b> 经 emSign ECC G3 根；<b>native</b> 使用用途专属自签名根；<b>aaa</b> 使用 Sectigo AAA 交叉签名。</p><p>客户端原本信任的根和用途各不相同。随机选择适合抽查，完整验收需遍历各身份及链路。</p></section><section class="panel mini-guide"><span class="eyebrow">03 / SIGN</span><h2>📦 软件与 JAR</h2><p>需要原始文件，单独摘要不足以生成完整签名。软件调用 osslsigncode，JAR 调用 JDK jarsigner；支持工具自定义路径。</p><p>普通运行程序不代表进行了签名信任检查，应在实际加载器、安装器或执行策略中验证。</p></section><section class="panel mini-guide"><span class="eyebrow">04 / RECORD</span><h2>📋 如何判读结果</h2><p>明确报“CA 已吊销 / 已封禁”才支持该路径的吊销判断。根不受信任、CT、域名、算法、有效期错误均应单独记录。</p><p>成功获取页面也可能来自手动忽略错误或中间代理。请设置正常受信任的正向对照端点。</p></section></div><section class="panel mini-guide"><h2>⌘ 常用命令</h2><pre class="cli-examples">fakeca web
fakeca web --listen 127.0.0.1:8080 --open=false
fakeca generate --type tls --domain "*.demo.com,demo.com" --out out/tls-test
fakeca serve --bundle out/tls-test --listen 192.168.10.20:8443
fakeca sign --type jar --bundle out/jar-test --input test.jar --output out/signed.jar
fakeca help generate</pre><h3>📁 当前 Web 工作目录</h3><code class="break-anywhere">{{ directory }}</code><p class="field-hint">上传文件、自动生成证书及历史索引保存在此。路径参数指向运行 FakeCA 的服务器，不是浏览器所在设备。</p></section>
        </template>
        <footer class="footer">FakeCA / Trust Verification Lab<span>时间按浏览器本地时区显示 · 测试产物生成成功，不等于信任验证通过。</span></footer>
      </div>
    </main>
  </div>

  <el-drawer :model-value="!!detail" title="📋 证书包详情" size="min(680px, 96vw)" @close="detail = null">
    <template v-if="detail"><div class="detail-title"><el-tag>{{ reportTypeName(detail.report) }}</el-tag><h2 class="mono">{{ detail.report.ca.id }}</h2><p class="muted">{{ chainName(detail.report.ca.chain) }}</p></div><el-tabs v-model="detailTab"><el-tab-pane label="概览" name="overview"><dl class="detail-list"><dt>输出目录</dt><dd>{{ detail.path }}</dd><dt>证书身份</dt><dd>{{ reportIdentity(detail.report) }}</dd><dt>生效时间</dt><dd>{{ time(detail.report.not_before) }}</dd><dt>到期时间</dt><dd>{{ time(detail.report.not_after) }}</dd><dt>终端证书 SHA-256</dt><dd class="mono">{{ detail.report.leaf_sha256 }}</dd><dt>CA 证书 SHA-256</dt><dd class="mono">{{ detail.report.ca.sha256 }}</dd></dl><el-alert title="所选 CA 已失守并被吊销，这是负向信任测试产物。" type="warning" :closable="false" show-icon /><div class="detail-actions"><el-button type="primary" @click="download(detail)">下载完整 ZIP</el-button><el-button v-if="detail.report.type === 'tls'" @click="useForService(detail)">启动 TLS 服务</el-button><el-button v-else @click="useForSign(detail)">用于文件签名</el-button></div></el-tab-pane><el-tab-pane label="文件下载" name="files"><p class="field-hint">完整 ZIP 包含终端私钥及可能存在的 P12 密码，请妥善保管。</p><div v-for="file in files" :key="file.name" class="file-row"><div><b class="mono">{{ file.name }}</b><small>{{ size(file.size) }}</small></div><el-button link type="primary" @click="download(detail, file.name)">下载</el-button></div></el-tab-pane><el-tab-pane label="JSON 报告" name="report"><el-button size="small" @click="copy(JSON.stringify(detail.report, null, 2))">复制报告</el-button><pre class="report-json">{{ JSON.stringify(detail.report, null, 2) }}</pre></el-tab-pane><el-tab-pane label="签名日志" name="logs"><pre class="report-json">{{ detail.logs || '暂无签名日志。' }}</pre></el-tab-pane></el-tabs></template>
  </el-drawer>
  <el-dialog v-model="serviceDialog" title="🌐 启动 TLS 测试服务" width="min(540px, 94vw)"><el-form label-position="top"><el-form-item label="TLS 证书包"><el-select v-model="serviceForm.bundle_id" placeholder="请先生成或导入 TLS 证书包"><el-option v-for="b in tlsBundles" :key="b.id" :label="`${b.report.ca.id} · ${b.report.ca.chain} · ${reportIdentity(b.report)}`" :value="b.id" /></el-select></el-form-item><el-form-item label="监听地址"><el-input v-model="serviceForm.listen" placeholder="127.0.0.1:8443" /><p class="field-hint">内网测试改为服务器内网 IP:端口；使用 127.0.0.1 仅本机可访问。</p></el-form-item></el-form><template #footer><el-button @click="serviceDialog = false">取消</el-button><el-button type="primary" :loading="busy === 'start'" :disabled="!serviceForm.bundle_id" @click="startService">启动服务 →</el-button></template></el-dialog>
  <el-dialog v-model="logDialog" title="📋 TLS 诊断日志" width="min(800px, 94vw)"><pre class="report-json">{{ serviceLogs }}</pre></el-dialog>
</template>
