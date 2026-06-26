# CPU 性能分析与优化建议

> 分析基于 Cloudflare Pages 环境，CPU 时间指标：
> - p50: 4,012 μs (4ms)
> - p75: 7,663 μs (7.7ms)
> - p99: 112,433 μs (112ms)
> - p99.9: 1,019,006 μs (~1秒)

---

## 一、CPU 消耗分布分析

### 1.1 常规请求（p50 ~4ms）

正常代理请求的 CPU 消耗分布：
- **路由和配置初始化**: 约 30%（`读取config_JSON`、环境变量解析、URL 路由）
- **协议首包解析**: 约 20%（VLESS/Trojan 首包解析、UUID 匹配）
- **连接建立和转发**: 约 40%（TCP 拨号、上行队列初始化、connectStreams）
- **日志/辅助操作**: 约 10%

### 1.2 尾延迟（p99.9 ~1s）的主要原因

| 原因 | 说明 |
|------|------|
| **KV 读取延迟波动** | `读取config_JSON` 每次请求都读取 KV，KV 的 p99 延迟可达 200-500ms |
| **自定义 TLS 握手** | `httpsConnect` 中的完整 TLS 1.3 握手涉及 ECDHE 密钥生成、证书解析、多个 HMAC 计算 |
| **DoH 查询超时** | `DoH查询` 在反代 IP 解析和预加载竞速拨号中被调用，慢响应会阻塞连接建立 |
| **Shadowsocks 密码扫描** | `初始化入站解密状态` 尝试多个候选密码配置进行 AES-GCM 解密直到成功 |
| **订阅生成重负载** | 大批量优选 IP 的 regex 匹配和字符串操作 |
| **并发连接竞争** | `TCP并发拨号数=2` 时，若所有候选连接都慢，等待超时（1000ms）才回退 |

---

## 二、VLESS 协议专项优化分析

> 以下分析基于你使用 VLESS 协议的前提（非 Trojan/Shadowsocks）

### 2.1 VLESS 请求处理流程中的 CPU 热点

以下是 VLESS 请求在三种传输模式下的关键路径：

#### WS 模式（最常用）
```
处理WS入站数据(第1422行)
  ├── 协议类型检测(第1439行) — 仅比较2字节(bytes[56]和bytes[57])，极快 ✓
  ├── 解析魏烈思请求(第1465行)
  │     ├── UUID字节匹配(第1672行) — 16字节比较，已用Map缓存 ✓
  │     ├── 地址类型解析(第1686行) — switch/case，开销小 ✓
  │     └── 域名解码(第1697行) — TextDecoder.decode，不可避免 ✗
  └── forwardataTCP(第1479行)
```

#### XHTTP 模式
```
读取XHTTP首包(第680行) 
  ├── 尝试解析木马首包(第822行) — 先行解析Trojan！每次计算sha224(纯JS)！
  ├── 尝试解析魏烈思首包(第825行) — 然后才解析VLESS
  └── 两者都invalid则返回null
```

#### gRPC 模式
```
处理gRPC请求(第839行)
  ├── gRPC帧解析(第996行) — 5字节头+变长载荷解析，不可避免
  ├── 判断VNEXT类型(第1033行) — 检查bytes[56-57]是否为0x0d/0x0a
  ├── 解析木马请求(第1035行) — 尝试Trojan
  └── 解析魏烈思请求(第1048行) — 然后才VLESS
```

### 2.2 VLESS 优化点详解

#### 优化 V1：消除 XHTTP 路径中不必要的 Trojan 预解析（🔥最高收益）

**问题**: `读取XHTTP首包` 中每次接收数据块都先尝试 Trojan 解析（`尝试解析木马首包`），而 Trojan 解析内部会调用 `sha224(token)` —— 这是一个纯 JavaScript 实现的 SHA-224，包含 64 轮位运算/块。对于 VLESS 用户来说，这个计算完全浪费。

**代码位置**: `_worker.js` 第 821-828 行
```javascript
const 木马结果 = 尝试解析木马首包(当前数据); // ← sha224(token) + 56字节比较
if (木马结果.状态 === 'ok') return { ...木马结果.结果, reader };
const 魏烈思结果 = 尝试解析魏烈思首包(当前数据); // ← 然后才尝试VLESS
if (魏烈思结果.状态 === 'ok') return { ...魏烈思结果.结果, reader };
if (木马结果.状态 === 'invalid' && 魏烈思结果.状态 === 'invalid') return null;
```

**原理**: Trojan 首包至少需要 58 字节（56 字节密码哈希 + 2 字节 `\r\n`）。当数据小于 58 字节时，Trojan 必然 invalid，可以跳过。另外 VLESS 首字节 `data[0]` 是版本号（当前为 0），Trojan 首字节是 SHA-224 哈希的第一个字节（分布随机），理论上可以先用 `data[0] === 0` 做快速预判，但这不够可靠。

**优化方案**: 交换尝试顺序 + 加快速长度检查
```javascript
// 优化后
const 数据长度 = 当前数据.byteLength;
// VLESS 首包最小长度 18 字节（1版本+16UUID+1附加长度）
if (数据长度 >= 18) {
    const 魏烈思结果 = 尝试解析魏烈思首包(当前数据);
    if (魏烈思结果.状态 === 'ok') return { ...魏烈思结果.结果, reader };
    // 仅当数据足够长时才尝试 Trojan
    if (数据长度 >= 58 && 魏烈思结果.状态 !== 'ok') {
        const 木马结果 = 尝试解析木马首包(当前数据);
        if (木马结果.状态 === 'ok') return { ...木马结果.结果, reader };
    }
}
if (数据长度 >= 58) return null;
// 数据不足，继续等待
```

**预期效果**: 消除 XHTTP 模式下每个 VLESS 连接的 `sha224()` 计算。sha224 在纯 JS 中约需 5-20μs 执行，累积在 p99 场景中效果显著。

---

#### 优化 V2：缓存用户身份标识（userID）和 Token（🔥高收益）

**问题**: 每次 `fetch()` 调用都执行：
1. `MD5MD5(管理员密码 + 加密秘钥)` — 2 次 `crypto.subtle.digest('MD5')` + hex 转换
2. 从 MD5 结果拼接 UUID 格式
3. `MD5MD5(host + userID)` — 在订阅路径中再次调用
4. 其他各处 `MD5MD5` 调用

**代码位置**: `_worker.js` 第 30-35、86、91、4955、5104 行

**原理**: `管理员密码` 和 `加密秘钥` 来自 `env.ADMIN` 和 `env.KEY`，在同一个 Worker 实例内不会变化。`userID` 一旦算出就稳定不变。可以缓存到模块级变量。

**优化方案**:
```javascript
// 在模块作用域（export default 外部）
let 缓存userID = null;
let 缓存userID已初始化 = false;

// 在 fetch 内部
if (!缓存userID已初始化) {
    const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
    const envUUID = env.UUID || env.uuid;
    缓存userID = (envUUID && uuidRegex.test(envUUID)) 
        ? envUUID.toLowerCase() 
        : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
    缓存userID已初始化 = true;
}
const userID = 缓存userID;
```

**同时缓存 `MD5MD5` 结果**:
```javascript
const MD5MD5缓存 = new Map();
async function MD5MD5(文本) {
    const key = 文本;
    if (MD5MD5缓存.has(key)) return MD5MD5缓存.get(key);
    // ...原有计算逻辑...
    if (MD5MD5缓存.size < 1024) MD5MD5缓存.set(key, 结果);
    return 结果;
}
```

**提示**: `host` 可变（不同域名访问），所以 `MD5MD5(host + userID)` 不能无限制缓存。但 `管理员密码 + 加密秘钥` 绝对是常量。

**预期效果**: 消除每次请求的 2 次 MD5 计算 + 2 次 hex 转换。MD5 在 `crypto.subtle` 中虽快（~2-5μs），但 hex 转换有数组分配和 GC 压力。p50 可降约 5-10%。

---

#### 优化 V3：消除 UUID 解析缓存 32 条限制（中收益）

**问题**: `UUID字节缓存` 在条目达到 32 时会整体清空（`UUID字节缓存.clear()`），导致下一个请求的 UUID 字符串需要重新解析（32 个 hex 字符 → 16 字节）。

**代码位置**: `_worker.js` 第 1653 行
```javascript
if (UUID字节缓存.size >= 32) UUID字节缓存.clear();
```

**原理**: 单用户部署通常只有 1 个 UUID。32 条的容量基本不会触发，但如果触发（如使用大量不同订阅源的场景），clear() 会无效化缓存。

**优化方案**:
```javascript
// 方案 A：增大上限或移除限制（单用户场景安全）
// if (UUID字节缓存.size >= 32) UUID字节缓存.clear();  // ← 直接注释掉

// 方案 B：更优雅的 LRU 限制
if (UUID字节缓存.size >= 256) {
    const firstKey = UUID字节缓存.keys().next().value;
    UUID字节缓存.delete(firstKey);
}
```

**预期效果**: 避免偶发的 UUID 重解析，对 p99 有轻微帮助。

---

#### 优化 V4：消除 WS 模式中的不必要的 `数据转Uint8Array` 调用（低收益）

**问题**: 在 `处理WS入站数据` → `解析魏烈思请求` 的调用链中：
```javascript
function 解析魏烈思请求(chunk, token) {
    const data = 数据转Uint8Array(chunk);  // ← chunk 从 bytes 来，已经是 Uint8Array
    ...
}
```
`数据转Uint8Array` 对 Uint8Array 会直接返回（已经是 no-op），但函数调用本身有开销。

**原理**: 检查调用方——`处理WS入站数据` 中的 `bytes` 已在第 1464 行通过 `数据转Uint8Array(chunk)` 转换过，传到 `解析魏烈思请求` 时已是 Uint8Array，所以内部不会再转换。但 `处理gRPC请求` 中传入的可能是经过 gRPC 帧解析后的 subarray，也是 Uint8Array。

**优化方案**: 不需要改动，`数据转Uint8Array` 对 Uint8Array 输入 return 自身，开销只有一个 `instanceof` 检查。✅ 保持。

---

#### 优化 V5：预分配 VLESS 响应头（低收益）

**问题**: VLESS 连接建立时需要返回响应头 `new Uint8Array([version, 0])`，在 WS 处理（第 1473 行）、gRPC 处理（第 1057 行）中各有分配。

**代码位置**: 
- `_worker.js:1473` — `const respHeader = new Uint8Array([version, 0]);`
- `_worker.js:1057` — `const respHeader = new Uint8Array([version, 0]);`
- `_worker.js:735` — `respHeader: new Uint8Array([data[0], 0])`

**优化方案**: 使用模块级常量（VLESS 当前版本始终是 0）:
```javascript
const VLESS_RESP_HEADER = new Uint8Array([0, 0]);  // 模块级常量
// 使用时
respHeader: VLESS_RESP_HEADER
```

**预期效果**: 每个连接减少一次 2 字节的数组分配，微小优化。

---

#### 优化 V6：合并两个 VLESS 解析器（代码维护收益）

**问题**: 代码中存在两个功能几乎相同的 VLESS 首包解析器：
1. `尝试解析魏烈思首包`（第 683 行，XHTTP 专用，内联在 `读取XHTTP首包` 中）
2. `解析魏烈思请求`（第 1667 行，WS/gRPC 共用）

两者都做 VLESS 首包解析，但返回格式不同：
- XHTTP 版返回 `{状态: 'ok'/'invalid'/'need_more', 结果: {协议, hostname, port, isUDP, rawData, respHeader}}`
- 通用版返回 `{hasError, message, port, hostname, version, isUDP, rawClientData}`

**问题**: 修改一个不会同步修改另一个，可能出现行为不一致。共享同一个解析函数还能让 JIT 有更多类型反馈信息。

**优化方案**: 将 `解析魏烈思请求` 改造为同时支持两种调用约定，或在 XHTTP 中直接调用 `解析魏烈思请求`。

**预期效果**: 维护性收益为主，CPU 收益有限（因为 XHTTP 模式已不常用）。

---

### 2.3 VLESS 优化优先级总表

| 序号 | 优化 | 难度 | 预期 p50 收益 | 预期 p99 收益 | 改动行数 |
|------|------|------|---------------|---------------|----------|
| V1 | XHTTP 路径跳过 Trojan 预解析 | 低 | 5-10% (XHTTP模式) | 10-20% (XHTTP模式) | ~10 行 |
| V2 | userID + MD5MD5 缓存 | 低 | 5-10% | 2-5% | ~15 行 |
| V3 | UUID 缓存不限 32 条 | 低 | <1% | 1-3% | 1 行 |
| V4 | 不需要改动 | 无 | — | — | 0 |
| V5 | VLESS 响应头常量 | 低 | <1% | <1% | 2 行 |
| V6 | 合并 VLESS 解析器 | 中 | 维护收益 | 维护收益 | ~50 行 |

### 2.4 VLESS 路径上无法优化的项

| 项 | 原因 |
|----|------|
| **VLESS 首包中的域名解码** | `TextDecoder.decode(data.subarray(...))` 是必要的，无法跳过 |
| **地址类型 switch/case** | 必须根据 addressType 选择解析方式，复杂度为 O(n) |
| **forwardataTCP 中的连接建立** | 无论什么协议，TCP 连接建立时间都取决于远端网络 |
| **TLS 握手** | VLESS 的 `security=tls` 需要完整的 TLS 1.3 握手，这是设计使然 |

---

## 三、可在 Cloudflare Pages 优化的项目（通用）

### 优化 3.1：读取config_JSON 缓存（🔥高优先级）

### 优化 1：MD5MD5 结果缓存（高优先级）

```javascript
const MD5MD5缓存 = new Map();
async function MD5MD5(文本) {
  const key = 文本;
  if (MD5MD5缓存.has(key)) return MD5MD5缓存.get(key);
  // ...原有逻辑...
  MD5MD5缓存.set(key, 结果);
  return 结果;
}
```

**影响**: `MD5MD5` 每次请求调用多次（认证 Token、订阅 Token 等），每次调用做 2 次 `crypto.subtle.digest('MD5')` + 数组遍历 + hex 拼接。缓存后 p50 可降低 5-10%。

### 优化 2：sha224 结果缓存（高优先级）

```javascript
const sha224缓存 = new Map();
function sha224(s) {
  if (sha224缓存.has(s)) return sha224缓存.get(s);
  // ...原有纯 JS 实现...
  sha224缓存.set(s, hex);
  return hex;
}
```

**影响**: `sha224(token)` 在 `是有效WS早期数据` 和 `解析木马请求` 中高频调用。纯 JS 实现的 SHA-224 是 CPU 密集操作，缓存后效果显著。注意 Trojan 密码 hash 通常对同一连接不变。

### 优化 3：读取config_JSON 缓存（高优先级）

```javascript
let config缓存 = null;
let config缓存时间 = 0;
const config缓存TTL = 5000; // 5秒

async function 读取config_JSON(env, hostname, userID, UA, 重置配置) {
  const now = Date.now();
  if (config缓存 && now - config缓存时间 < config缓存TTL && !重置配置) {
    return config缓存;
  }
  // ...原有KV读取逻辑...
  config缓存 = config_JSON;
  config缓存时间 = now;
  return config_JSON;
}
```

**影响**: `读取config_JSON` 每次请求都调用 `env.KV.get('config.json')`，KV 读操作有 20-200ms 延迟。缓存后几乎消除此开销。注意：配置变更后手动重置或等待 TTL 过期。

### 优化 4：DoH 查询缓存（中优先级）

```javascript
const DoH缓存 = new Map();
async function DoH查询(域名, 记录类型, ...) {
  const key = `${域名}:${记录类型}`;
  if (DoH缓存.has(key)) return DoH缓存.get(key);
  // ...原有逻辑...
  DoH缓存.set(key, 结果);
  return 结果;
}
```

**影响**: 在预加载竞速拨号中，同一域名会同时查询 A 和 AAAA 记录，且短时间内可能重复查询同一域名。DNS 缓存 TTL 可设为 60-300 秒。

### 优化 5：减少 UUID 解析/hex 转换（中优先级）

`MD5MD5` 中的 `Array.from(new Uint8Array(...)).map(b => ...)` 模式非常低效。可使用更快的 hex 转换：

```javascript
function toHex(bytes) {
  const hex = '0123456789abcdef';
  const result = new Array(bytes.length * 2);
  for (let i = 0; i < bytes.length; i++) {
    result[i * 2] = hex[bytes[i] >> 4];
    result[i * 2 + 1] = hex[bytes[i] & 15];
  }
  return result.join('');
}
```

或者直接用 `Array.prototype.reduce` 避免中间数组分配。

### 优化 6：正则表达式预编译（低-中优先级）

`SOCKS5白名单.some(p => new RegExp(...))` 在每次 `forwardataTCP` 调用中都重新创建正则。应预编译：

```javascript
let 白名单正则 = null;
// 初始化时：白名单正则 = SOCKS5白名单.map(p => new RegExp(...))
```

### 优化 7：减少 `读取config_JSON` 中的非必要 KV 读取（中优先级）

`读取config_JSON` 每次都读 `tg.json` 和 `cf.json`，但多数请求不需要这些配置。
可改为惰性加载：只在访问 `/admin` 路由或订阅生成时加载 `tg.json`/`cf.json`。

```javascript
// 在 config_JSON 中初始化 TG/CF 为默认值
// 仅当需要时再读取 KV
if (需要TG配置) {
  const TG_TXT = await env.KV.get('tg.json');
  // ...
}
```

### 优化 8：去除不必要的字符串操作（低优先级）

`替换星号为随机字符` 在订阅生成中每次生成 3-17 个随机字符，使用循环拼接字符串效率不高。可改为 `crypto.getRandomValues` + 预计算字符数组。

`随机路径` 中的 `.sort(() => 0.5 - Math.random())` 打乱数组，对大数组效率低。Fisher-Yates 洗牌更优。

---

## 三、Cloudflare Pages 平台限制导致的不可优化项

### 3.1 无法优化（平台限制）

| 限制 | 原因 |
|------|------|
| **KV 读取延迟** | 无法避免，KV 是按需读取的全球分布式存储。`读取config_JSON` 的三个 KV.get（config.json + tg.json + cf.json）累积延迟 |
| **WS/API 调用开销** | `crypto.subtle.*` 调用有固定的 IPC 开销，无法优化 |
| **TCP 连接建立时间** | 不可控因素，取决于远端服务器响应速度 |
| **DNS 解析时间** | `request.fetcher.connect()` 内建 DNS 解析，不受代码控制 |
| **Worker 冷启动** | Pages Function 冷启动时加载 290KB 脚本，增加首次 CPU 时间 |
| **内存限制** | 128MB 内存限制，大 Buffer 操作可能触发 GC 导致 CPU 尖刺 |

### 3.2 可部分缓解但本质难优化

| 项目 | 说明 |
|------|------|
| **自定义 TLS 握手** | 这是实现 HTTPS 代理的核心。`generateKeyShare`（ECDHE 密钥生成）+ `deriveSharedSecret` + `hkdfExpandLabel` 不可省，但可将结果缓存（按 serverName 缓存 ECDHE 结果？不能，安全原因） |
| **Shadowsocks 多候选密码扫描** | 可以优化扫描顺序（优先尝试上次成功的加密配置），但不能完全消除 |
| **大型 JSON 解析** | `读取config_JSON` 返回 JSON.stringify(config_JSON) 给管理页面时，对大对象的序列化有开销 |
| **请求体读取/解析** | gRPC 帧解析、XHTTP 首包读取都需要全量读取输入流 |
| **TCP并发拨号数=1 的运营商限制** | 移动网络下限制并发数为 1 是兼容性要求，无法绕过 |

### 3.3 潜在风险点

| 风险 | 说明 |
|------|------|
| **内存 OOM** | `上行队列最大字节 = 16MB` 接近 Worker 内存上限（128MB），多个并发连接可能 OOM |
| **CPU 超时** | p99.9 已达 1 秒，免费 Worker 有 10ms CPU 限制（付费 30s）。Pages Functions 的 CPU 时间限制类似 |
| **正则回溯** | 订阅生成中的复杂正则（如 IPv6 匹配 `^(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}$`）可能导致灾难性回溯 |
| **未捕获异常** | 大量 `try { ... } catch (e) { }` 吞掉错误，不利于调试 |
| **调试日志** | `调试日志打印` 开启后每个连接会输出大量 `log()` 调用，每条 log 写入 console 消耗 CPU |

---

## 四、推荐优化优先级排序

| 优先级 | 优化项 | 预期效果 |
|--------|--------|----------|
| P0 | MD5MD5 + sha224 缓存 | p50 降 10-15%，消除纯 JS 哈希重复计算 |
| P0 | 读取config_JSON 缓存 | p50 降 20-30%，消除每次请求的 KV 读取延迟 |
| P1 | DoH 查询缓存 | p75 降 5-10%，减少重复 DNS 查询 |
| P1 | 正则预编译 + 白名单缓存 | p50 降 2-5%，减少正则编译开销 |
| P2 | hex 转换优化 | p50 降 1-3%，减少内存分配和 GC |
| P2 | TG/CF 配置惰性加载 | p50 降 5-10%，减少非必要 KV 读取 |
| P3 | 随机路径/星号替换优化 | 微小优化，大量订阅生成时有效 |
| P3 | Shadowsocks 密码扫描顺序优化 | 减少 SS 模式下首次连接延迟 |
