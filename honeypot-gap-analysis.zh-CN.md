# 蜜罐能力补全分析(内网威胁捕捉 / 证据固定 / POC 收集)

> 基线:`github.com/zealot00/beelzebub` fork of `beelzebub-labs/beelzebub`(GPL-3.0)
> 分析日期:2026-11-12 · 全部结论带 `文件:行号`,可逐条回查

---

## 0.1 实施状态(2026-11-12,分支 `feature/event-bus-and-syslog`)

| 项 | 状态 | 落点 |
|---|---|---|
| **P0-1 事件总线** | ✅ 已实现 | `tracer.Strategy` 单值 → 多订阅者;新增 `pkg/plugin.EventSubscriber` + `RegisterEventHandler`;`Event` 提升到公共 SDK(`internal/tracer.Event` 保留为类型别名,JSON 不变) |
| **P0-2 多路输出** | ✅ 已实现 | `setTraceStrategies` / `addTraceStrategy`;`director.go` 改为 fan-out。**修掉了 Cloud 覆盖 RabbitMQ 的 bug**;顺带修了 `build()` 复制 builder 导致日志文件/RabbitMQ 通道/syslog 客户端不释放的问题 |
| **P0-3 统一事件模型** | ✅ 已实现(仅新增字段) | `Event` 新增 `EventID` / `SessionID` / `ConnID` / `Sequence` / `CorrelationKey`,全部 `omitempty`;HTTP/MCP 补来源会话;SSH/TELNET 认证尝试回挂到连接 |
| **syslog 管线**(附加需求) | ✅ 已实现 | `internal/builder/syslog.go`,RFC 5424 + RFC 6587,配置 `core.tracings.syslog`,支持 tcp/udp、TLS、懒连接与断线重连 |
| P0-5 样本落盘 | ⏳ 未开始 | 依赖 P0-1(已完成),可立即开工 |
| P0-6 LLM 脱敏 | ⏳ 未开始 | 独立小改,建议下一个 PR |

**新增的可用能力**(此前完全不存在):
- 插件可**订阅事件流** → 情报富化 / 工具指纹 / 证据处理终于有了落脚点
- **跨连接关联**:同一来源的所有事件共享 `CorrelationKey`,HTTP/MCP 的请求序列共享 `SessionID` 且 `Sequence` 递增
- **事件可送到中心日志服务器**:syslog 管线与本地日志、RabbitMQ、Cloud **并行**投递

**已知限制**(下一批要处理):
- 事件由 5 个 worker **并发分发**,到达顺序不保证 → 排序必须依赖 `Sequence`,不能依赖日志行顺序
- `Sequence` 只在事件带 `SessionID` 时分配
- `CorrelationKey` 只到「协议 + 服务地址 + 源 IP」粒度,**不含用户名**;SSH/TELNET 跨用户关联仍需靠 `SourceIp` + `User` 组合
- SSH 会话标识取自 SSH 传输层 session id(密钥交换派生),**不是** `ID` 字段里的 uuid

---

## 0. 一句话结论

当前产品是**「协议仿真 + 事件流记录器」**,不是**「威胁捕捉 + 取证系统」**。你列的四个目标里,「协议仿真」这层上游已经做得不错,**缺的不是功能而是地基**:

| 地基 | 现状 | 后果 |
|---|---|---|
| **① 事件流对插件完全封闭** | 插件只能"在事件发出前影响它"(且仅 TCP 的 `WirePlugin` 一条路),**不能观察它** | 情报富化 / 工具指纹 / 证据哈希 —— 你想补的三件事,全都无处落脚。这是所有补全项的前置 |
| **② 证据面是纯文本事件流,不是取证仓库** | 无 pcap、无样本落盘、无哈希链、无签名、无会话持久化 | 「证据固定」当前做不到 —— 不是做得不够好,是这一层压根不存在 |
| **③ 协议仿真深度不足以骗过真实工具** | MySQL 只有一个 `banner`,其余靠正则匹配字节流 | 真实渗透工具(nmap -sV / nuclei / exploit 脚本)会当场识破 → 根本「吸引」不到深度交互 |

**P0 只有一件事:把口子打开。** 在这之前写任何情报插件、指纹库、样本管理,都会发现没有接口可用。

---

## 1. 现状能力盘点(事实)

### 1.1 事件模型与捕获能力

`tracer.Event` 共 29 个字段(`internal/tracer/tracer.go:15-51`),全部是字符串类字段,**没有任何结构化的载荷/附件字段**。

| 协议 | 事件类型 | 会话关联 | 关键捕获 |
|---|---|---|---|
| HTTP | 1 类/请求 | ❌ **每请求独立 UUID**(`HTTP/http.go:196`) | URI/方法/Header/Cookie/UA/body(≤1MiB 硬编码) |
| SSH | 5 类 | ✅ 每连接 `uuidSession`(`SSH/ssh.go:39`) | 登录尝试(**含明文密码** + 客户端版本串 `Client`)、命令、环境变量 |
| TELNET | 5 类 | ✅ 每连接(`TELNET/telnet.go:150`) | 登录尝试(**明文密码**)、命令 |
| TCP | 5 类 | ✅ 每连接 `connID`(`TCP/tcp.go:500`) | 原始字节(`Command` latin1 重编码 + `CommandRaw` hex) |
| MCP | 1 类/工具调用 | ❌ **每次调用独立 UUID**(`MCP/mcp.go:80`) | 工具名 + 参数 map 的 `%s` 渲染 |

> **认证尝试与会话脱节**:SSH/TELNET 的登录尝试用全新 UUID(`SSH/ssh.go:195`、`TELNET/telnet.go:132`),与随后的会话 ID 无关 → 暴力破解序列在事件流里是断裂的。

### 1.2 存储与输出

| 能力 | 现状 | 证据 |
|---|---|---|
| 事件落盘 | logrus JSON 行 → `io.MultiWriter(stdout, logsFile)`,`O_APPEND\|O_CREATE\|O_RDWR`,**权限 0666** | `internal/builder/builder.go:51-55` |
| `logsPath` | **是文件不是目录**(默认 `./logs` 会创建一个名为 `logs` 的普通文件),单值不支持多路径 | `internal/builder/builder.go:51`、`configurations/beelzebub.yaml:6` |
| 日志完整性 | ❌ 无哈希链 / 无签名 / 无写前哈希 / 无只追加 / 无轮转 | 全仓 grep `hash\|hmac\|signature\|chain\|rotate` 无相关命中 |
| pcap / 原始报文 | ❌ 完全不存在 | 全仓 grep `pcap\|gopacket` → `*.go` 零命中 |
| 二进制样本落盘 | ❌ 不存在。运行期只有 2 处写文件:日志 + 插件锁文件 | grep `os.Create\|os.WriteFile\|os.OpenFile` |
| 持久化会话 | ❌ 无。`historystore` 只服务 LLM 上下文(内存、TTL 60 分钟、`history_store.go:11-12`) | `internal/historystore/history_store.go:15-26` |
| 多路输出 | ❌ **`setTraceStrategy` 是覆盖语义**(`builder.go:43-45`),`director.go:31→34→42` 顺序覆盖 → **RabbitMQ 与 Cloud 同时开,只有 Cloud 生效,RabbitMQ 静默失效** | `internal/builder/director.go:24-46` |
| 指标 | Prometheus 可选,默认关且不绑端口 | `internal/builder/builder.go:202-223` |

### 1.3 插件扩展面(最关键)

**插件接口清单**(`pkg/plugin/plugin.go`):

| 接口 | 能拿到 | 能输出 | 适用协议 |
|---|---|---|---|
| `CommandPlugin` | 攻击者命令文本、ClientIP、Protocol、History | 响应正文 | SSH/TCP/TELNET/HTTP body |
| `HTTPPlugin` | 完整 `*http.Request` | 状态码/头/body | HTTP |
| `ServicePlugin` | **只有一个 `ctx`** | — | 后台常驻服务 |
| `WirePlugin` | TCP 原始字节 `Request []byte`、Response、`ConnID`、`SessionKey` | 可改写 Response / CommandOutput / **Metadata** | **仅 TCP** |

**四个关键事实:**

1. **事件流对插件封闭。** `tracer.Strategy` 是单值函数类型(`internal/tracer/tracer.go:99`),worker 只调一个 strategy(`:162-169`),`SetStrategy` 是替换(`:176-180`)。`pkg/plugin` 全部导出符号与 `Event` 无关,也不 import 任何 `internal/` 包 → **外部插件连 `internal/tracer` 都 import 不到**。
2. **插件唯一能往事件里塞东西的通道是 `Event.Metadata map[string]string`**,且只有 TCP 的 wire plugin 走得到(`tcp.go:806`)。HTTP/SSH/TELNET **没有任何 wire plugin 等价挂载点**。
3. **仓库里没有任何 `ServicePlugin` 实现**,且它拿不到 tracer 句柄 —— 只能自己起 goroutine + ticker + 自持 HTTP client,读不到事件。
4. **插件配置是三处封闭集合**,新增任何配置项必须同步改:`specs/runtime-config.schema.json`(`additionalProperties: false`)、`internal/parser/configurations_parser.go:60-73`、`pkg/plugin/plugin.go:166-181`。schema 校验在启动时 fatal(`cli/run.go:77-83`),写错一个键就直接起不来。

### 1.4 协议仿真深度

| 协议 | 实现方式 | 能骗过谁 |
|---|---|---|
| Redis / Memcached | 纯文本正则 + 静态 handler | 手工命令行 |
| MySQL | **只有一个 `banner: "8.0.29"`**(`tcp-3306.yaml`) | 几乎骗不过任何工具 |
| MSSQL / RDP / SMB / LDAP / MQTT | 通用 `Framing` 分帧 + 正则 | 需要深度握手的工具会掉线 |
| VNC | 唯一有真实 wire plugin 的协议 | `tcp_wire_vnc.go`,含 DES challenge 提取 + John 格式输出 |
| HTTP | 静态 handler / Maze 迷宫 / LLM | 迷宫很真实(确定性种子 + 6 种技术栈 profile) |

**VNC 是全仓库唯一的「结构化凭据提取」范式**(`tcp_wire_vnc.go:75-79`:把 challenge/response 写进 `Event.Metadata`,产出 John the Ripper 可解格式)—— 这是你后面做 POC 收集可以直接抄的模板。

### 1.5 依赖能力

| 需要的能力 | 现状 |
|---|---|
| HTTP 客户端(查情报用) | ✅ `resty/v2` 已在生产使用 |
| 限流 | ✅ `golang.org/x/time/rate`,LLM 插件已按 IP 做 token bucket(`llm-integration.go:345-393`) |
| 哈希 | ✅ `crypto/sha256` / `golang.org/x/crypto` |
| GeoIP / ASN / IP 信誉库 | ❌ `go.mod`/`go.sum` **零命中** |
| 威胁情报 API 客户端 | ❌ 零命中 |
| 数据库驱动 / 存储引擎 | ❌ 零命中(sqlite/postgres/redis/mongo/bolt 全无) |
| 外部插件自带依赖 | ✅ 支持,manifest 声明 `Dependencies`,不进 core 的 go.mod(`pluginmgr/manifest.go:27`) |

---

## 2. 目标 → 缺口矩阵

### 2.1 内网威胁捕捉

| # | 缺口 | 证据 | 严重度 |
|---|---|---|---|
| A1 | **无跨连接关联**。同一攻击者的多条独立连接在事件流里无法聚合;`Event` 无 correlation/campaign/attacker 字段,`WireContext.SessionKey` 只活在插件进程内、从不进事件 | `tracer.go:15-51` 无相关字段 | P0 |
| A2 | **HTTP/MCP 无会话概念**,每请求/每次调用独立 UUID → Web 侧攻击链完全断裂 | `http.go:196`、`mcp.go:80` | P0 |
| A3 | **认证尝试与会话脱节**,暴力破解序列不可还原 | `ssh.go:195`、`telnet.go:132` | P1 |
| A4 | **HTTP/MCP 无读写超时**,裸 `http.ListenAndServe`,慢连接可挂住 goroutine(内网扫描器常慢) | `http.go:39,41`、`mcp.go` 无 deadline | P1 |
| A5 | **日志权限 0666 + 无轮转**,长期运行会撑爆磁盘且任何本地用户可读可改 | `builder.go:51` | P1 |
| A6 | **无内网资产对照能力**。内网场景下"这个源 IP 是哪台机器、是不是已知资产、有没有做过基线"远比公网 IP 信誉重要 —— 当前没有任何挂载点 | 见 §3 P1-2 | P1 |

### 2.2 吸引渗透进来的危险任务 / 代码

| # | 缺口 | 证据 | 严重度 |
|---|---|---|---|
| B1 | **协议仿真深度不足**,MySQL 只有 banner,真实工具秒识破 → 吸引不到深度交互 | `tcp-3306.yaml:1-6` | P2 |
| B2 | **无文件上传捕获**:multipart 全仓零处理,body 1MiB 上限硬编码且不可配,HTTP **无 `CommandRaw`** → 二进制上传失真不可恢复 | `http.go:118`;grep `multipart` 零命中 | P1 |
| B3 | **无诱饵文件投放能力** —— 不能反向给攻击者一个带水印的诱饵包做追踪(拿到包的机器即落地证据) | 不存在 | P2 |
| B4 | **无"漏洞型"响应原语**。当前只能静态字符串或迷宫,做不出"看起来真的能被打"的登录页/上传点/备份接口 | YAML 表达能力所限 | P2 |
| B5 | **MCP 响应完全静态**(`handler` 写死),无法随攻击者行为演化;**且不记录 agent 身份**(无 clientInfo/session/UA/header/body) | `mcp.go:70-86`、`mcp.go:92-94` | P1 |
| B6 | **LLM 把攻击者输入原样外发,零脱敏**。HTTP 场景下整个 body 被拼进 prompt(`http.go:129`),prompt 还被 `log.Debug` 打进日志(`llm-integration.go:292,328`)。内网数据出境 + 内容拦截会打断表演 | 同上 | P0(合规) |

### 2.3 证据固定

| # | 缺口 | 证据 | 严重度 |
|---|---|---|---|
| C1 | **无 pcap / 原始报文留存** → 无法还原协议级证据(如 MySQL 握手包、SMB 命令) | 全仓零命中 | P1 |
| C2 | **无样本落盘设施** → 上传的 webshell/恶意脚本无法成为可归档样本 | 运行期仅 2 处写文件 | P0 |
| C3 | **日志无完整性保护**,0666 权限下可静默篡改 → 不能作为证据链 | `builder.go:51` | P0 |
| C4 | **无持久化会话对象**,一次攻击的完整上下文只在内存里 60 分钟 | `history_store.go:11` | P0 |
| C5 | **无事件序号 / 单调时间**,事件只有 `DateTime`(秒级 RFC3339),无法证明时序与唯一性 | `tracer.go:16,189` | P1 |
| C6 | **密码明文入日志**(SSH/TELNET)→ 既是证据也是泄露面,需要分级存储/脱敏策略 | `ssh.go:190`、`telnet.go` | P1 |
| C7 | **无证据打包导出** —— 一次会话无法导出成"可归档、可移交、带 manifest 和 sha256" 的包 | 不存在 | P1 |
| C8 | **无 NTP 时钟保障与审计日志**,证据时间基准不可证 | 不存在 | P2 |

### 2.4 POC 收集与渗透工具整理(后续)

| # | 缺口 | 证据 | 严重度 |
|---|---|---|---|
| D1 | **无样本库**:没有 sha256 去重、没有元数据、没有存储 | 无 DB/文件 API | P0(依赖 C2) |
| D2 | **无工具指纹识别逻辑**。原料其实齐全 —— SSH `Client` 版本串、HTTP `UserAgent`、TCP 原始字节 —— 但没有任何识别/归类代码 | `ssh.go:191`、`http.go:188`、`WireContext.Request` | P1 |
| D3 | **无命令归一化与分类**,无 ATT&CK 映射。命令是自由文本,统计不出"最常用横向手段" | 全仓无 taxonomy | P1 |
| D4 | **无法区分"投递"与"取回"**。上传 webshell 和下载 webshell 在事件里形态相近,但后者才是利用成功的铁证 | 无下载语义建模 | P1 |
| D5 | **无对内外网渗透工具库的特征库**(Metasploit / Cobalt Strike / Sliver / Viper / 天蝎等的默认端口、默认 UA、默认请求体指纹) | 不存在 | P2 |
| D6 | **无样本与情报的关联**(样本 hash ↔ 情报 ↔ 攻击者) | 不存在 | P2 |

---

## 3. 补全清单(按优先级)

### P0 — 先开口子,否则后面全是空中楼阁

| ID | 补全项 | 落点(精确到文件) | 工作量 | 依赖 |
|---|---|---|---|---|
| **P0-1** | **事件总线改造**:把 `tracer.Strategy` 从单值改成订阅者列表,新增 `pkg/plugin.EventSubscriber` 接口(插件可 `Subscribe(func(Event))`) | `internal/tracer/tracer.go:99`(类型)、`:162-169`(worker 循环)、`:176-180`(替换→广播)、`pkg/plugin/plugin.go`(新接口) | M(核心改动 + 回归) | 无 |
| **P0-2** | **多路输出修复**:director 改为 fan-out 链,修掉 RabbitMQ 被 Cloud 静默覆盖的 bug | `internal/builder/director.go:31-43`、`internal/builder/builder.go:43-45` | S | P0-1 |
| **P0-3** | **统一事件模型**:`EventID` / `SessionID` / `ConnID` / `Sequence` / `CorrelationKey` 五者分离;补 HTTP/MCP 的会话 ID;把 SSH/TELNET 认证尝试挂回会话 | `internal/tracer/tracer.go:15-51`;`http.go:196`、`mcp.go:80`、`ssh.go:195`、`telnet.go:132` | M | 无 |
| **P0-4** | **取证存储层**:append-only 写入 + sha256 哈希链 + 会话清单 + 打包导出(会话 → zip + manifest + 逐文件 sha256);权限收到 0600 | 新增包(如 `internal/evidence/`);`internal/builder/builder.go:51` 替换 | L | P0-1、P0-3 |
| **P0-5** | **样本落盘 + sha256 去重**:HTTP body / TCP 原始字节 / MCP 参数 命中阈值即落盘为样本,写 sha256 + 元数据 | 复用 `Event.Metadata` 范式(`tcp.go:806`);需新增文件 API | M | P0-1 |
| **P0-6** | **LLM 出站脱敏**:攻击者输入进 prompt 前做可配置脱敏(至少:禁发全 body、禁发凭据字段、默认关 debug 落 prompt) | `internal/plugins/llm-integration.go:206-209,292,328`;`internal/protocols/strategies/HTTP/http.go:129` | S | 无(可与 P0 并行) |

### P1 — 能力主体

| ID | 补全项 | 落点 | 依赖 |
|---|---|---|---|
| P1-1 | **威胁情报富化插件**:订阅事件 → 查 IP 信誉/ASN/GeoIP → 写回 `Metadata` | 新插件包,`plugin.EventSubscriber` | P0-1、P0-3 |
| P1-2 | **内网资产对照**:源 IP → CMDB/资产表 → 判定"已知资产 / 未知主机 / 跳板机"(**内网场景最该先做的一块**) | 同上,内网数据源 | P0-1 |
| P1-3 | **攻击工具指纹库**:SSH Client 串 + HTTP UA + TCP 字节特征 → 归一化工具名 | 新包 + 规则文件 | P0-1 |
| P1-4 | **命令归一化 + ATT&CK 映射**:命令 → 分类(探测/提权/横向/持久化/数据) | 新包 | P0-1、P1-3 |
| P1-5 | **HTTP 抓取面补齐**:body 上限可配、multipart 解析、二进制走 `CommandRaw`、响应体也记录 | `http.go:117-123`;`specs/runtime-config.schema.json` + `parser` + `pkg/plugin.Config` 三处同步 | 三处封闭集合 |
| P1-6 | **MCP 补齐**:记录 agent 身份(clientInfo/UA/header/body)、会话 ID、prompt-injection 标注 | `mcp.go:70-94` | P0-3 |
| P1-7 | **超时与限流**:HTTP/MCP 加 Read/Write/Idle 超时;全局每源 IP 连接速率上限 | `http.go:39-41`、`mcp.go:96` | 无 |
| P1-8 | **日志工程化**:轮转、权限 0600、`logsPath` 支持目录、可配置保留期 | `builder.go:47-71`;`parser` | 无 |
| P1-9 | **pcap 留存**(可选:只对命中的会话抓包,避免全量开销) | 新包 + `tcpdump`/libpcap 或旁路抓包 | P0-3 |
| P1-10 | **"取回"语义**:区分投递(上传)与取回(下载),后者标高危并单独告警 | HTTP 事件需带响应侧信息 | P1-5 |
| P1-11 | **凭据分级存储**:明文密码不落普通日志,单独加密区 + 访问审计 | `ssh.go:190` 等 | P0-4 |

### P2 — 深度与体验

| ID | 补全项 | 说明 |
|---|---|---|
| P2-1 | **协议仿真深化**:MySQL 真实握手包、Redis AUTH/SLAVEOF、SMB SessionSetup | 决定"吸引"上限;建议先做 MySQL(内网最常被打) |
| P2-2 | **诱饵文件投放 + 水印追踪**:给攻击者一个带唯一水印的包,下载即落地 | 抓"谁拿了包"最有效的手段 |
| P2-3 | **LLM 本地化 + 脱敏后启用**:自托管模型走 OpenAI 兼容端点(`plugin.host` 已支持) | 配合 P0-6 |
| P2-4 | **证据移交包**:一次事件 → 可移交的取证包(含说明、时间基线、完整性清单) | 依赖 P0-4 |
| P2-5 | **外网渗透工具特征库** | 依赖 P1-3 |
| P2-6 | **样本 ↔ 情报 ↔ 攻击者关联图** | 依赖 P1-1、P0-5 |

---

## 4. 架构落点图:口子开在哪

```
协议策略层  internal/protocols/strategies/{HTTP,SSH,TCP,TELNET,MCP}
   │  构造 tracer.Event
   ▼
事件构造点  http.go:181 · ssh.go:80/185 · tcp.go:749 · telnet.go:123 · mcp.go:73
   │
   ▼
Tracer     internal/tracer/tracer.go:188  TraceEvent → eventsChan
   │  ★ P0-1 在这里开口子:Strategy 单值 → 订阅者列表
   ▼
Worker     internal/tracer/tracer.go:162-169   ← 广播点(现在只调一个 strategy)
   │
   ▼
装配层     internal/builder/director.go:31-43   ← P0-2 fan-out 修复点
   │
   ├── standardOutStrategy  (director.go:48)
   ├── rabbitMQTraceStrategy(director.go:76)
   ├── beelzebubCloudStrategy(director.go:55)
   │
   ▼
★ P0-4 取证存储(新)      ★ P1-1 情报富化插件(新)      ★ P1-3 工具指纹(新)
```

**插件侧三个可用挂载点**(不用改 core 就能先上手的部分):

| 挂载点 | 能做什么 | 限制 |
|---|---|---|
| `WirePlugin`(`pkg/plugin/plugin.go:62`) | TCP 层原始字节 → 指纹/哈希写回 `Metadata` | **仅 TCP** |
| `CommandPlugin`(`:31`) | 命令文本 → 工具识别 / 归一化 | 无原始字节 |
| `ServicePlugin`(`:46`) | 后台定时拉情报、写存储 | **读不到事件** |

---

## 5. 建议实施顺序

**Sprint 1(地基,2~3 周)**
1. P0-1 事件总线 + P0-2 fan-out(一起做,回归测试覆盖三种 strategy 组合)
2. P0-3 统一事件模型(补 HTTP/MCP 会话、认证尝试回挂)
3. P0-4 取证存储层(哈希链 + 会话清单 + 打包导出)
4. P0-6 LLM 脱敏(独立小改,别拖)

**Sprint 2(能力,3~4 周)**
5. P0-5 样本落盘 + sha256 去重 → 直接产出 POC 库雏形
6. P1-1 + P1-2 情报富化 + **内网资产对照**(内网场景优先级高于公网 IP 信誉)
7. P1-3 + P1-4 工具指纹 + 命令归一化 → 产出"常见渗透工具"清单
8. P1-5 + P1-6 HTTP/MCP 补齐

**Sprint 3(深度)**
9. P1-9 pcap、P2-1 协议仿真深化、P2-2 诱饵投放

---

## 6. 明确不建议现在做的

| 项 | 理由 |
|---|---|
| 先写情报插件再改架构 | 事件流封闭,插件拿不到事件,写完也无法落地 |
| 先做 AI Agent 对接 | 当前 MCP 只有静态 bait tool、无 agent 身份、无会话。先补齐 P1-6,再做"AI agent 横向探测"的识别才有数据基础 |
| 上 Beelzebub Cloud | 内网捕获内容出境到第三方;且 Cloud 开启会覆盖 RabbitMQ(P0-2 未修前是坑) |
| 先做广度(再多加几个协议诱饵) | 上游已有 19 个配置,广度不是瓶颈;深度与证据链才是 |
| 引入数据库 | 当前阶段 append-only 文件 + sha256 索引就够,少一个依赖少一份运维 |

---

## 附:已确认**不存在**的能力(全仓搜索核实)

| 能力 | 核实方式 |
|---|---|
| pcap / 原始报文抓包 | grep `pcap\|gopacket\|tcpdump` → `*.go` 零命中 |
| 二进制样本 / 上传文件落盘 | grep `os.Create\|os.WriteFile` → 运行期仅日志与锁文件 |
| 日志哈希链 / 签名 / 只追加 / 轮转 | grep `hash\|hmac\|signature\|chain\|rotate` → 命中全是无关项 |
| 按源 IP 的攻击者聚合索引 | grep `byIP\|aggregate\|groupBy` → 零命中;`Event` 29 字段无相关字段 |
| 持久化会话对象 | 全仓仅 `historystore`(内存)与 TCP 连接内 struct |
| MCP 的 agent 身份 / clientInfo / session | grep `clientInfo\|Initialize\|SessionID` → 零命中 |
| HTTP multipart 解析 | grep `multipart\|ParseMultipartForm\|FormFile` → 零命中 |
| HTTP 读/写超时 | grep `ReadTimeout\|WriteTimeout\|IdleTimeout` → 仅 SSH 命中 |
| RabbitMQ 与 Cloud 双写 | `setTraceStrategy` 为直接赋值覆盖 |
| 多日志路径 / 日志目录 | `LogsPath` 是单 `string`,直接传给 `os.OpenFile` |
| 通用凭据提取(除 VNC) | `tcp_wire_vnc.go:75-79` 是唯一实现 |
| 插件侧事件订阅 / 拦截 | `pkg/plugin` 导出符号与 `Event` 无关;`internal/` 不可被外部模块 import |
