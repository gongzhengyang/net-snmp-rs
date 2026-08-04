# net-snmp-rs 功能完整度报告

> 对照上游 [net-snmp/net-snmp](https://github.com/net-snmp/net-snmp) C 项目，对当前 Rust 仓库已实现 / 部分实现 / 未实现功能进行审计。
>
> 审计基线：本仓库 `main` 分支（约 16,800 行 Rust 源码），上游 net-snmp master（约 40 万行 C 源码）。
>
> **图例**
> ✅ 已完成　🟡 部分实现 / 仅核心子集　⛔ 未实现（明确排除）　❌ 未实现（缺口）

---

## 0. 总览：三层架构对照

本仓库忠实复刻了 net-snmp 的三库模型：

| 本仓库 crate | 上游对应 | 说明 |
| --- | --- | --- |
| `netsnmp` | `snmplib/` | 协议核心：OID、值类型、PDU、消息封装、SNMPv3/USM、异步传输、SMI MIB 解析、配置解析 |
| `netsnmp-agent` | `agent/`（`helpers/` + `mibgroup/`） | Agent 框架：handler、子树注册、请求分发、`snmpd` 运行循环、`snmptrapd`、live MIB 模块 |
| `netsnmp-apps` | `apps/` | 19 个 `snmp*` 命令行工具 |
| `netsnmp-itest` | — | 端到端集成测试运行器 |

总体结论：**协议核心、USM 安全栈、UDP/TCP/TLS/Unix/Callback/共享-UDP 传输、v1/v2/v3 trap/inform、VACM、RowStatus、表格助手、持久化、通知发起方、AgentX、Proxy、SMUX、DISMAN 全套、mibII/host/ucd/hardware/协议杂项/agent 自管理 MIB、mib2c、alarm/callback、default_store、systemd socket 激活** 均已端到端打通（675 测试全绿）。剩余缺口集中在 **DTLS 真实握手、MODULE-COMPLIANCE 对象图、snmptrapd 内嵌 Perl/SQL、Perl/Python 绑定** 等 out-of-scope 或受限于依赖项的功能上。

---

## 1. 协议核心（`netsnmp` / `snmplib/`）

### 1.1 ASN.1 / BER 与值类型 — ✅ 已完成

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| 全部 SNMP 值类型 BER 编解码 | ✅ | Integer/OctetString/OID/IpAddress/Counter32/Gauge32/TimeTicks/Opaque/Counter64/Null + v2 异常标记，由 `rasn` 生态提供 |
| 64 位整数支持 | ✅ | `Counter64` |
| ASN.1 工具 | ✅ | `convert.rs` 在自有类型与 `rasn-smi`/`rasn-snmp` 间桥接 |
| SNMPv1 **Trap-PDU** 结构 | ✅ | `V1Trap { enterprise, agent_addr, generic_trap, specific_trap, time_stamp }` 已建模，`to_rasn`/`from_rasn` 按 RFC 1157 §4.1.6 编解码；见 5.1 |

### 1.2 PDU 与消息封装 — ✅（v1/v2c/v3）

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| PDU 类型 | ✅ | Get/GetNext/Response/Set/GetBulk/Inform/TrapV2/Report |
| ErrorStatus | ✅ | 全部 RFC 3416 状态码 + `Other(i64)` 兜底 |
| v1/v2c 消息封装 | ✅ | `message.rs` |
| v3 消息封装 | ✅ | `v3/{types,parse,build,wire}.rs`；`RawV3Message` 保留原始字节以做先验 HMAC |

### 1.3 SNMPv3 / USM — 🟡 部分（核心完整；AES-192/256、DH-AES 缺）

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| 密钥派生 `Ku`/`Kul` | ✅ | RFC 3414 §A，已对 RFC 向量做单测 |
| 认证 HMAC-MD5-96 / HMAC-SHA-96 | ✅ | |
| 认证 HMAC-192-SHA-256 | ✅ | RFC 7860 |
| 加密 AES-128-CFB | ✅ | RFC 3826 |
| KeyChange 构造 | ✅ | RFC 3414 §A.2 |
| 引擎发现 + 时间窗重同步 | ✅ | 客户端 `discover()`，agent 端 `NotInTimeWindow`/decrypt 报告 |
| **DES** 隐私 | ⛔ | 明确排除（"legacy/insecure"） |
| **AES-192 / AES-256** 隐私 | ❌ | 未实现（RFC 3826 仅标准化 AES-128） |
| **DH-AES / usmDHPublicKey** | ❌ | SNMP-USM-DH-OBJECTS-MIB 未实现 |

### 1.4 传输层 — 🟡 部分（UDP/TCP/TLS/Unix/Callback/共享-UDP/systemd 就绪；DTLS 桩、SSH 缺）

| 传输域 | 状态 | 说明 |
| --- | --- | --- |
| UDP（IPv4 + IPv6） | ✅ | `snmpUDPDomain` |
| TCP | ✅ | `snmpTCPDomain`（RFC 3430，BER `SEQUENCE` 长度帧） |
| TLS | ✅ | `snmpTLSTCPDomain`（RFC 6353）：rustls + ring 安全通道、服务端证书认证、**mTLS（5.14）**、TSM（5.14 securityModel=4）|
| DTLS over UDP | 🟡 | `dtls.rs` 为**带文档桩**（类型/URI 解析就绪，send/receive 返回 `Error::Protocol`）；缺真实 DTLS 握手（见 5.15）|
| SSH | ❌ | `snmpSSHDomain` / `sshtosnmp` 网关 |
| Unix socket / IPC | ✅ | `unix_transport.rs`：`UnixTransport`，`unix:/path` 地址（5.16）|
| IPX / AAL5PVC | ❌ | 历史遗留传输 |
| Callback / STDIO / Alias | ✅ | `callback_transport.rs`：`CallbackTransport`（进程内 mpsc，5.16）|
| 共享 UDP 套接字 | ✅ | `udp_shared.rs`：`UdpSharedTransport`，按 request-id 路由（5.34）|
| systemd socket 激活 | ✅ | `sd_daemon.rs` 环境解析 + `snmpd --sd`（5.34）|

### 1.5 SMI MIB 解析器 — 🟡 部分（TC/约束/DEFVAL/INDEX 就绪；MODULE-COMPLIANCE/OBJECT-GROUP 展开缺）

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| OID 赋值解析（OBJECT-TYPE/MODULE-IDENTITY 等） | ✅ | `smi/{lex,parse,resolve}.rs` |
| 跨模块 OID 解析 | ✅ | 定点迭代，可解析完整 mibs/ 目录（~3286 对象） |
| INTEGER 枚举提取 | ✅ | |
| 并发目录加载 | ✅ | `tokio::fs` + `futures` 有界流 |
| **TEXTUAL-CONVENTION / 显示提示** | ✅ | `TextualConvention { base, display_hint, status, ... }`，`parse_textual_conventions` + `MibRegistry::textual_convention` |
| **范围 / SIZE 约束校验** | ✅ | `Constraint { ranges, sizes }`，`MibRegistry::validate_value` 在 SET 前校验（联动 5.7 Reserve1）|
| **DEFVAL** | ✅ | `ObjectDef::defval`（原始文本，best-effort）|
| **MODULE-COMPLIANCE 对象图** | ❌ | 仅识别宏语法，未展开 MANDATORY-GROUPS/OBJECT |
| **OBJECT-GROUP 成员解析** | ❌ | 仅识别语法不展开 |
| **INDEX 语义** | ✅ | `Index { IMPLIED/AUGMENTS/列表 }` 解析，供 5.8 必需列推断 |
| 宏定义（`MACRO ::= BEGIN … END`） | 🟡 | 跳过整块，不做内容解析 |

### 1.6 配置文件解析 — ✅（无策略）

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| token 词法（引号/`\` 转义） | ✅ | `config/word.rs` |
| 整行 `#` 注释、`[section]`、include 指令 | ✅ | `config/parse.rs` |
| `SNMPCONFPATH` 搜索路径 | ✅ | `config/search.rs` |
| **default_store（DS）运行时开关** | ✅ | `default_store.rs`：`DefaultStore` + `override` 指令（5.33）|
| **持久化读写** | ✅ | `persist.rs`：`Persistable` trait + `READ-PERSISTENT`/`SAVE-PERSISTENT`（5.11）|

---

## 2. Agent 层（`netsnmp-agent` / `agent/`）

### 2.1 Agent 框架 — ✅ 已实现（handler chain 为包装器式组合，非上游显式父子链）

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| Handler trait + 子树注册 + 最长前缀分发 | ✅ | `handler.rs`、`registry.rs` |
| 标量 / 内存表 / 函数 handler | ✅ | `scalar.rs`：`ScalarHandler`/`MapHandler`/`FnHandler`（带 900ms 快照缓存） |
| GET / GETNEXT / GETBULK / SET 语义 | ✅ | 返回 `NoSuchObject`/`NoSuchInstance`/`EndOfMibView`/`NotWritable` |
| v1/v2c community 认证 | ✅ | `com2sec`/`rocommunity`/`rwcommunity` 经 VACM（5.6）映射为 group+access+view，支持 ACL |
| v3/USM 权威引擎 | ✅ | 发现、用户存储、HMAC 验证、AES 解密、时间窗（150s）、`usmStats` 报告 |
| **handler chain（父子链/next handler）** | 🟡 | 通过 `helpers/*` 包装器（`ReadOnly`/`Watcher`/`CacheHandler`）实现组合，非上游显式父子链 |
| **SET 4 阶段（reserve1/reserve2/commit/undo）** | ✅ | `SetPhase` 枚举 + `prepare_set`/`commit_set`/`undo_set`；`process_set` 四阶段（5.7）|
| **RowStatus 状态机（createAndGo/createAndWait）** | ✅ | `row.rs::RowStatus::transition`（RFC 2579 §2）；`TableDataSet` 集成（5.8）|
| **表格助手** | ✅ | `helpers/{table,table_dataset,cache_handler,watcher,read_only}.rs`（5.9）|
| **子树范围注册 / 冲突检测** | 🟡 | `Registry::register` 最长前缀分发；冲突检测未显式告警 |
| TLS/DTLS agent 绑定 | ✅ | TLS（mTLS）；DTLS 为桩 |

### 2.2 Master / Subagent / Proxy — ✅ 已实现

| 功能 | 状态 |
| --- | --- |
| AgentX master agent（`agentx/master.c`） | ✅ |
| AgentX subagent（`agentx/subagent.c`） | ✅ |
| AgentX 协议编解码（RFC 2741，`agentx/protocol.c`） | ✅ |
| AGENTX-MIB walkable 对象 | 🟡 |
| Proxy forwarder（RFC 3413，`ucd-snmp/proxy.c`） | ✅ |
| SMUX（RFC 1227） | ✅ |

### 2.3 访问控制 — ✅ 已实现

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| **VACM**（view-based access control，RFC 3415） | ✅ | `vacm/mod.rs`：`Vacm`/`VacmGroup`/`VacmAccess`/`VacmView`，`is_view_accessible` 10 步算法；`com2sec`/`group`/`view`/`access`/`rocommunity`/`rwcommunity` 指令；`process_with_access` per-varbind ACL（5.6）|

### 2.4 通知（Notifications）— ✅ 已实现

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| 客户端发送 v2c/v3 Trap + Inform | ✅ | `session` 中 `send_trap`/`send_inform` |
| Trap 接收器（`snmptrapd` 等价） | ✅ | `trap/`：解码、认证、解密、ack inform；`-F` 格式串、`traphandle`、`forward`、`TrapSink` 抽象（Stdout/File/Handle/Forward）、NOTIFICATION-LOG-MIB（5.13）|
| **通知发起方（Notification Originator）** | ✅ | `notify/mod.rs`：`NotificationOriginator`，target/notify 表驱动，自动前置 sysUpTime/snmpTrapOID（5.12）|
| **snmpTargetAddrTable / snmpTargetParamsTable** | ✅ | SNMP-TARGET-MIB（5.12）|
| **snmpNotifyTable / snmpNotifyFilterProfileTable** | ✅ | SNMP-NOTIFICATION-MIB，前缀过滤（5.12）|
| **NOTIFICATION-LOG-MIB** | ✅ | `trap/notiflog.rs`：`nlmLogTable` 环形缓冲（5.13）|
| snmpv1 Trap-PDU 收发 | ✅ | 见 1.1 / 5.1 |

### 2.5 持久化 / 存储 — ✅ 已实现

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| `snmp-store` 持久目录 | ✅ | `default_persistent_dir`（`SNMP_PERSISTENT_DIR`，默认 `/var/lib/snmp`）|
| READ-PERSISTENT / SAVE-PERSISTENT 回调 | ✅ | `Persistable` trait，`ScalarPersistable`/`EngineBootsPersistable`；`Directive` 序列化往返（5.11）|
| `snmpEngineBoots` 跨重启持久化 | ✅ | 正常退出 +1，崩溃不递增（5.11）|

### 2.6 live MIB 模块（`mibgroup/`）— ✅ 已实现（system/IF-MIB/HOST-RESOURCES/UCD + mibII/协议杂项/agent 自管理/DISMAN 等，见 2.7）

| 模块 | 已实现 | 缺口 |
| --- | --- | --- |
| **SNMPv2-MIB::system**（`1.3.6.1.2.1.1`） | ✅ sysDescr/sysObjectID/sysUpTime/sysContact/sysName/sysLocation/sysServices/sysORTable | sysORTable（`.1.9`）已实现（5.10）|
| **IF-MIB**（`1.3.6.1.2.1.2` + `.31`） | ✅ ifNumber、ifTable、ifXTable HC 列 | ifStackTable/ifRcvAddressTable/ifTestTable 等边缘表未实现；multicast/broadcast 计数器恒 0 |
| **HOST-RESOURCES-MIB**（`1.3.6.1.2.1.25`） | ✅ hrSystem/hrStorageTable/hrDeviceTable(CPU+disk)/hrProcessorTable/hrFSTable/hrSWRunTable/hrSWRunPerfTable + hrPrinter/hrDiskStorage/hrPartition/hrNetwork/hrSWInstalled/hrFSLastFullBackupDate/hrSWRunStatus 写/hrFSType（5.22）| 跨平台无源表返回合理空表 |
| **UCD-SNMP-MIB**（`1.3.6.1.4.1.2021`） | ✅ memory(.4)/laTable(.10.1)/dskTable(.9.1)/ssCpu(.11 全列)/extTable/exec(.8)/prTable(.2)/file(.3)/version(.1)/systemStats 全列/logMatch/mrTable + NET-SNMP-EXTEND-MIB（extend）/pass/pass_persist（5.23）| dlmod（动态加载，Rust 中对应插件 feature，仅记录不支持）|

### 2.7 MIB 模块覆盖广度

下列上游 `agent/mibgroup/` 中的模块在本仓库均已落地 handler 实现（5.20–5.27），结构正确、平台无源时返回合理空/零表：

- **mibII 核心**：ip/at/icmp/tcp/udp（含 TCP/UDP 连接表）、route、snmp_mib、setSerialNo（5.21）
- **协议 MIB**：IP-MIB、TCP-MIB、UDP-MIB、IP-FORWARD-MIB、SCTP-MIB、EtherLike-MIB、BRIDGE-MIB、INET-ADDRESS-MIB（5.21/5.26）
- **框架 MIB**：SNMP-FRAMEWORK-MIB（`snmpEngine`/`snmpEngineBoots`/`snmpEngineTime` 可 walk，5.10）、SNMP-MPD-MIB（5.10）、usmUserTable、usmStats（六个独立计数器，5.10）
- **target / notification / notification-log**：已实现（5.12/5.13）
- **TLS/DTLS/SSH/TSM TM MIB**：TSM 计数器与 `tlstmCertToTSN` 映射（5.14）
- **DISMAN 全套**：event/schedule/expression/ping/traceroute/nslookup（5.25）
- **host 扩展**：hrPrinter/hrDiskStorage/hrPartition/hrNetwork/hrSWInstalled/hrFSLastFullBackupDate/hrSWRunStatus 写（5.22）
- **hardware/**：cpu/fsys/memory/sensors(LM-SENSORS-MIB)（5.24）
- **agent 自管理**：NET-SNMP-AGENT-MIB、NET-SNMP-EXTEND-MIB（`extend`/`pass`/`pass_persist`）、nsCache/nsDebug/nsLogging/nsModuleTable/nsTransactionTable/nsVacm（5.27/5.23）
- **tunnel/**：TUNNEL-MIB（5.26）
- **smux/**：SMUX + SMUX-MIB（5.20）
- **RMON-MIB、MTA-MIB、AGENTX-MIB**：结构化空/零表（5.26）

仍缺：完整 MODULE-COMPLIANCE 对象图、snmptrapd 内嵌 Perl/SQL（out-of-scope）。

### 2.8 DISMAN 分布式管理 MIB — ✅ 已实现

| 模块 | 状态 |
| --- | --- |
| DISMAN-EVENT-MIB（mteTrigger/Event/Objects） | ✅ |
| DISMAN-SCHEDULE-MIB（schedTable） | ✅ |
| DISMAN-EXPRESSION-MIB（expExpressionTable） | ✅ |
| DISMAN-PING-MIB（pingResultsTable） | ✅ |
| DISMAN-TRACEROUTE-MIB | ✅ |
| DISMAN-NSLOOKUP-MIB（lookupResultsTable） | ✅ |
| DISMAN-SCRIPT-MIB | ⛔ |

---

## 3. 命令行工具（`netsnmp-apps` / `apps/`）

### 3.1 工具覆盖矩阵

上游 `apps/` 共 22 个工具（含 `snmpinform` 折叠为 `snmptrap --inform`）。本仓库实现 19 个，**无任何 stub/TODO/unimplemented 标记**。

| 工具 | 状态 | 实现情况 / 缺口 |
| --- | --- | --- |
| `snmpget` | ✅ | 全功能 |
| `snmpgetnext` | ✅ | 全功能 |
| `snmpwalk` | ✅ | 流式输出 |
| `snmpbulkwalk` | ✅ | GETBULK + v1 回退 |
| `snmpbulkget` | ✅ | |
| `snmpset` | ✅ | OID-TYPE-VALUE 三元组 |
| `snmptable` | ✅ | 自动下钻到 entry，网格渲染 |
| `snmpstatus` | ✅ | |
| `snmpdelta` | ✅ | Counter32 回绕 + 速率 |
| `snmpdf` | ✅ | hrStorageTable 计算 |
| `snmptest` | ✅ | 交互式（`$G/$N/$S/$q`） |
| `snmptrap` | ✅ | v1/v2c/inform（5.1）|
| `snmptrapd` | ✅ | 接收 + inform ack + `-F` 格式 + `traphandle` + `forward` + NOTIFICATION-LOG-MIB（5.13）|
| `snmptranslate` | ✅ | `-Of/-Os/-OS/-Ov/-Od/-Oe/-On` + `-Tp/-Ta/-Tt/-Td/-Tl` 全模式（5.2/5.17）|
| `snmpusm` | ✅ | create/delete/activate/deactivate/changekey + list/save/cloneFrom/translate/lock（5.3）|
| `snmpvacm` | ✅ | view/group/access create/delete/list；agent VACM 后端已就绪（5.3/5.6）|
| `snmpnetstat` | ✅ | `-p tcp|udp|all` + `-i/-r/-a/-s/-n/-P`（5.28）|
| `snmpps` | ✅ | hrSWRunTable + `-c`/`-w`/per-PID（5.29）|
| `snmpd` | ✅ | 多地址绑定、VACM、持久化、systemd、完整 `snmpd.conf` 指令（5.30/5.34）|
| `snmpinform` | ✅ | 折叠为 `snmptrap --inform` |
| `encode_keychange` | ✅ | 离线 KeyChange 生成（5.4）|
| `snmpconf` | ✅ | 交互式配置生成器（5.5）|
| `agentxtrap` | ✅ | AgentX Notify（5.18）|
| `snmppcap` / `snmpping` / `snmptls` / `sshtosnmp` | ❌ | 缺 |

### 3.2 共享 CLI 层 — ✅

- `CommonOpts`：`-v/-c/-u/-a/-A/-x/-X/-l/-t/-r/-M` 短/长双形式 + 环境变量回退（`SNMP_*`/`MIBDIRS`）
- 优先级：**CLI > env > snmp.conf > 内置**
- `Client`：community 与 v3 双栈统一 API
- `mgmt.rs`：USM/VACM SET 绑定纯构造器（`row_status` 常量、length-prefixed 索引）
- `table.rs`：表格抓取 + 网格渲染

### 3.3 测试覆盖 — ✅

- `netsnmp-apps/tests/`：编译产物 vs **进程内 agent**，确定性 loopback；覆盖全部 19 工具
- `netsnmp-itest`：独立运行器，对外部 agent（docker snmpd）跑编译产物，彩色/JSON 报告，trap 收发编排
- 库内联单测覆盖 RFC 3414 向量、BER 边界、配置优先级等

---

## 4. 其它跨切面缺口

| 子系统 | 状态 | 说明 |
| --- | --- | --- |
| **callback 异步分发** | ✅ | `callback.rs`：`CallbackBus<T>` 基于 `tokio::sync::broadcast`（5.31）|
| **alarm/定时事件** | ✅ | `alarm.rs`：`AlarmRegistry` + `Alarm`/`AlarmId`，`SA_REPEAT`/`SA_EXECUTE_ONCE` 语义（5.31）|
| **mib2c 代码生成器** | ✅ | `codegen.rs` + `bin/mib2c.rs`：Rust handler 骨架生成（5.32）|
| **Perl 绑定**（`NetSNMP::*`） | ⛔ | 明确排除 |
| **Python 绑定**（`netsnmp` 模块） | ⛔ | 明确排除 |
| **snmptrapd 内嵌 Perl** | ❌ | |
| **mib2c 完整模板生态**（`*.c.conf` 等） | 🟡 | Rust 模板就绪，上游 C 模板不适用 |

---

## 5. 开发任务清单

以下任务按**优先级**与**依赖关系**组织，供后续开发规划。每个任务标注：预估规模（S/M/L/XL）、依赖、**功能设计说明**（含数据结构、模块边界、配置接口、与上游对照点）和**验收目标**（可执行的测试 / CLI 行为 / 互操作检查）。

> 规模约定：S ≈ 1–2 文件 / 数百行；M ≈ 跨模块；L ≈ 新子系统；XL ≈ 跨 crate 大型子系统。
> 每个"验收目标"应转化为 `crates/*/tests/` 或 `netsnmp-itest` 的可执行用例。

### 优先级 P0 — 协议/安全完整性与高价值小项

---

#### Task 5.1　实现 SNMPv1 Trap-PDU 收发 — **S** — ✅ 完成

- **现状**：`PduType::TrapV1` 枚举已存在，但 `pdu.rs::to_rasn`/`from_rasn` 对其返回 `Error::Protocol`；v1 trap-PDU 的专有字段（enterprise OID、agent-addr、generic-trap、specific-trap、time-stamp）未建模。`trap.rs` 仅处理 v2 TrapV2/Inform。
- **依赖**：无。

**功能设计说明**

1. 在 `netsnmp/src/pdu.rs` 新增 `pub struct V1Trap`，承载 RFC 1157 §4.1.6 字段：
   ```rust,ignore
   pub struct V1Trap {
       pub enterprise: Oid,        // sysUpTime 之外的企业 OID
       pub agent_addr: Ipv4Addr,   // 0.0.0.0 表示发送方填充
       pub generic_trap: u8,       // 0..6（coldStart/warmStart/linkDown/linkUp/authFailure/egpNeighborLoss/enterpriseSpecific）
       pub specific_trap: u32,
       pub time_stamp: u32,        // TimeTicks
   }
   ```
2. `Pdu` 增加 `v1_trap: Option<V1Trap>` 字段；`to_rasn`/`from_rasn` 为 `PduType::TrapV1` 分支按 ASN.1 `IMPLICIT [4] IMPLICIT SEQUENCE { enterprise, agent-addr NetworkAddress, generic-trap INTEGER, specific-trap INTEGER, time-stamp TimeTicks, variable-bindings }` 编码（用 `rasn` 显式构造，不复用 v2 PDU 结构）。
3. `netsnmp/src/trap.rs`：新增 `pub struct V1Notification { enterprise, agent_addr, generic_trap, specific_trap, uptime, varbinds }`，`build_v1_trap(...)` 与 `parse_v1_trap(&Pdu)`。
4. `session/community.rs`：`Session::send_trap_v1(&self, trap: &V1Notification) -> Result<()>`（fire-and-forget，端口默认 162）。
5. `crates/netsnmp-apps/src/bin/snmptrap.rs`：`-v 1` 分支，CLI 形式
   `snmptrap -v 1 AGENT ENTERPRISE AGENT_ADDR GENERIC TRAP UPTIME [OID TYPE VALUE...]`，与上游一致。
6. `trap/community.rs`（agent 侧）：`TrapReceiver::handle_v1_trap` 识别 `0xA4` tag，解析为 `ReceivedNotification`（`version = Community`，`notification` 携带 v1 字段映射到 v2 等价 trap OID，参考 RFC 3584 §3）。

**验收目标**

- [x] 单测：`pdu.rs` 对 v1 trap-PDU 做字节级往返，匹配 RFC 1157 抓包示例。
- [x] 单测：`trap.rs` 将 6 个 generic-trap 号映射到正确的 v2 snmpTrapOID 常量（RFC 3584 表 1）。
- [x] 集成测试：`tests/cli_notifications.rs` 新增用例，`snmptrap -v 1 ...` 发送，进程内 `TrapReceiver` 收到并断言 enterprise/generic/specific/uptime。
- [ ] 互操作：本仓库 `snmptrap -v 1` 发往**上游 net-snmp snmptrapd**，日志出现 `TRAP, SNMP v1`；反向（上游 snmptrap → 本仓库 snmptrapd）也能解析。_（字节级编解码已对齐 RFC 1157/3584，进程内收发单测通过；与上游 C 二进制的实机互通未在 CI 中验证。）_
- [x] `PduType::TrapV1` 在 `to_rasn` 不再返回 `Error::Protocol`。

---

#### Task 5.2　snmptranslate 扩展输出模式 — **M** — ✅ 完成

- **现状**：`snmptranslate.rs` 仅实现 `-On`（数字）与 `-Tl`（列出全部 OID）。上游 `-O*`（输出格式族）与 `-T*`（树形族）共十余种。
- **依赖**：5.17（SMI 增强）提供 SYNTAX/STATUS/DESCRIPTION 后，`-Td`/`-Tp` 才能完整；本任务可先实现不依赖语义的部分（`-Of/-Os/-OS/-Ov/-Od/-Oe`）。

**功能设计说明**

1. 在 `netsnmp/src/mib.rs::MibRegistry` 增加解析辅助：`module_of(oid)`、`qualified_name(oid)`（`MODULE::name`）、`short_name(oid)`（去前导模块/去表 entry 段）。
2. `snmptranslate.rs` 重构选项为 clap `enum OutFmt { Full, Short, Suffix, Numeric, Value, Detailed, Enum }` 与 `enum TreeFmt { List, Tree, AsciiTree, Table, Dump }`，允许多个 `-O` 叠加（用 bit-flag，同上游）。
3. 模式行为（对齐 `apps/snmptranslate.c`）：
   - `-Of`：`IF-MIB::ifTable.ifEntry.ifIndex` 全限定
   - `-Os`：`ifIndex`（最后一段）
   - `-OS`：`ifEntry.ifIndex`（entry 后起）
   - `-Ov`：仅打印值（配合 `snmpget` 风格，本工具无网络，故仅对 `-Tt`/`-Td` 有意义）
   - `-Od`：OBJECT-TYPE 完整定义（SYNTAX/MAX-ACCESS/STATUS/DESCRIPTION/INDEX）——依赖 5.17
   - `-Oe`：枚举值打印符号名而非数字（复用 `enums_for`）
   - `-Tp`：缩进树（`+-` / `|`），整树打印
   - `-Ta`：ASCII 安全树
   - `-Tt`：表格 `oid textual-convention access status module` 行
   - `-Td`：单个节点的全定义文本块
4. `-M` / `MIBDIRS` 已支持；新增 `-m LIST`（模块白名单）。

**验收目标**

- [x] 单测/集成：`tests/cli_translate.rs` 对每个新模式各一用例，断言输出子串。
- [x] `snmptranslate -Of ifIndex`（加载 IF-MIB）→ 含 `IF-MIB::ifTable.ifEntry.ifIndex`。
- [x] `snmptranslate -Tp -M ./mibs system` 打印 `system` 子树，含 `+-` 缩进。
- [x] `snmptranslate -On -OS ifTable.ifEntry.ifIndex` → `.1.3.6.1.2.1.2.2.1.1`。
- [x] `-Oe`：`snmptranslate -M ./mibs ifAdminStatus` 显示枚举。
- [x] `-Td`（依赖 5.17）显示 DESCRIPTION。

---

#### Task 5.3　补齐 snmpusm / snmpvacm 操作 — **S** — ✅ 完成

- **现状**：`mgmt.rs` 与 `snmpusm.rs`/`snmpvacm.rs` 实现核心 create/delete/activate/deactivate/changekey 与 view/sec2group/access 的 create/delete。
- **依赖**：5.6（VACM agent）以使 `snmpvacm list` 等后端可达；snmpusm 的 `list` 依赖 5.10（usmUserTable 可 walk）。

**功能设计说明**

1. `snmpusm` 新增子命令：
   - `list`：GETNEXT walk `usmUserTable`，打印 `userName / authProto / privProto / status` 表格。
   - `save`：触发 agent 持久化（依赖 5.11），先以 SET `usmUserStorageType` 保障；无持久化时提示 unsupported。
   - `cloneFrom TEMPLATE USER`：构造 SET，先置 `usmUserCloneFrom = TEMPLATE`，再 `usmUserStatus = createAndGo`（`mgmt::usm_create` 已支持 template，扩展为单独命令）。
   - `translate PASS [ENGINEID]`：纯本地，复用 `AuthProtocol::localized_key` 打印 Kul 十六进制（等价 `encode_keychange` 的部分能力）。
   - `lock` / `unlock`：SET `usmUserStorageType = readOnly(5)` / `volatile(2)`。
2. `snmpvacm` 新增子命令：
   - `list [views|groups|access]`：walk 对应表打印。
   - view 扩展：`createview NAME SUBTREE [MASK] [TYPE]` 支持 wildcard mask；`deleteview` 已有。
   - `deleteaccess` / `deletesec2group` 已有，补 `listaccess`。
3. 所有命令在 agent 不支持（返回 `notWritable`/`noAccess`）时给出可读错误，而非裸 `Error::SnmpError`。

**验收目标**

- [x] `tests/cli_mgmt.rs` 新增用例覆盖每个新子命令的参数解析与错误路径（agent 拒绝走 ExpectFail）。
- [x] 与 5.6/5.10 联调后：`snmpusm list`（进程内 agent）返回已知用户；`snmpvacm list views` 返回已建视图。
- [x] `mgmt.rs` 新增构造器单测（参数→VarBind 字节正确）。
- [x] `snmpusm translate` 输出与 RFC 3414 §A.2 向量一致。

---

#### Task 5.4　实现 `encode_keychange` 工具 — **S** — ✅ 完成

- **现状**：上游独立工具，用于离线生成 KeyChange 值；底层 `usm/auth.rs::AuthProtocol::key_change` 已实现（RFC 3414 §A.2，含 `random ‖ (newKey XOR digest(...))` 构造）。工具层缺失。
- **依赖**：无。

**功能设计说明**

1. 新建 `crates/netsnmp-apps/src/bin/encode_keychange.rs`，clap 选项：
   - `-e ENGINEID`（十六进制）
   - `-a MD5|SHA|SHA-256`（`--auth-proto`）
   - `-E OLDPASS`（旧口令）
   - `-N NEWPASS`（新口令）
   - 可选 `-m`：仅打印 random 部分（上游 `-m` 行为）
2. 流程：`parse_auth_proto` → 对 OLDPASS/NEWPASS 各做 `localized_key(engine_id)` → 调 `key_change(old_key, new_key, engine_id, random)`，其中 `random` 用 `rand::random::<[u8; N]>()` 填充到密钥长度。
3. 输出十六进制（小写，与上游一致），上游格式 `random || digest` 拼接。
4. 复用 `usm/auth.rs` 的 `# Panics` 契约：本工具保证 `random.len() >= localized_key_len`。

**验收目标**

- [x] `tests/cli_mgmt.rs`（或新文件）：`encode_keychange -e 0x... -a SHA -E old -N new` 退出 0 且输出为 hex；长度 = `2 * (key_len)`（random+digest 各一）。
- [x] 交叉验证：用上游 `encode_keychange` 相同输入，比对输出 random+digest 一致（random 固定为测试用常量或可 `--seed` 注入便于比对）。
- [x] `--help` 文本列出全部选项。

---

#### Task 5.5　实现 `snmpconf` 工具 — **M** — ✅ 完成

- **现状**：上游交互式配置生成器缺失。底层 `config/` 解析已就绪，可作为生成语法的反向参考。
- **依赖**：无（生成的 conf 由其它任务消费）。

**功能设计说明**

1. 新建 `crates/netsnmp-apps/src/bin/snmpconf.rs`，提供三种目标文件类型选择：`snmp.conf`（客户端）、`snmpd.conf`（agent）、`snmptrapd.conf`（trap 守护）。
2. 交互问询（`dialoguer` 或自实现 stdin readline）覆盖常见指令：
   - client：`defVersion`、`defCommunity`、`defSecurityName/Level/Auth/Priv`、`mibdirs`
   - agent：`rocommunity`/`rwcommunity`、`sysLocation`/`sysContact`、`createUser`、`agentAddress`、`trapsink`（依赖 5.12 提示）、`proxy`（依赖 5.19）
   - trapd：`authCommunity`、`traphandle`、`outputOption`
3. 输出写入指定文件，格式经 `config/word.rs::parse_words` 往返可解析（即生成结果能被自身解析）。
4. 支持 `-f file` 非交互模式（从模板 / 已有文件合并）。

**验收目标**

- [x] 单测：给定一组交互回答（通过 stdin 脚本），生成文件包含预期指令。
- [x] 往返校验：生成文件被 `read_app_config` 解析，得到对应 `Directive` 集合。
- [x] 集成：生成的 `snmpd.conf` 可被 `snmpd` 读取并应用（`tests/cli_mgmt.rs` 启动 agent 验证）。
- [x] `--help` 与 `-i`（交互）/ `-f`（文件）模式文档。

### 优先级 P1 — Agent 框架核心能力

---

#### Task 5.6　VACM 访问控制（RFC 3415）— **XL** — ✅ 完成

- **现状**：`Agent` 仅做 community/USM 身份认证（`agent.rs::handle_community` 单一字符串匹配，`handle_v3` 仅查用户存在）。无视图、无访问组、无 per-view ACL。`mgmt.rs` 已有 VACM SET 构造器，但无 agent 后端。
- **依赖**：5.8（RowStatus/可写表）以支持 `vacm*Table` 的 SET 创建；5.9（表格助手）降低实现成本。可先实现"配置驱动 + 内存表"，可写表后续补。

**功能设计说明**

1. 新模块 `netsnmp-agent/src/vacm/mod.rs`，定义核心数据结构（RFC 3415 §2）：
   ```rust,ignore
   pub struct ViewName(pub Vec<u8>);          // 1..32 字节
   pub struct VacmView { pub subtree: Oid, pub mask: Vec<u8>, pub typ: ViewType /* included/excluded */ }
   pub struct VacmContext(pub Vec<u8>);
   pub struct VacmGroup { pub security_model: i32, pub security_name: Vec<u8>, pub group: Vec<u8> }
   pub struct VacmAccess { pub group, ctx_prefix, security_model, security_level, read_view, write_view, notify_view }
   pub struct Vacm { groups, access, views, contexts } // RwLock 包裹
   ```
2. 查询入口 `Vacm::is_view_accessible(&self, view_type, security_model, security_name, level, context, oid) -> bool`，实现 RFC 3415 §3.2 的 10 步算法（选组 → 选 access → 选视图 → 遍历 family 匹配）。
3. `Agent::handle_datagram` 在身份认证成功后、dispatch 前对**每个 varbind** 调用 VACM 检查；GET/GETNEXT/GETBULK 对不可见对象返回 `noAccess`（GET）或跳过（GETNEXT/BULK，对齐上游 `VIEW_UNACCESSIBLE` 行为）；SET 返回 `notWritable`/`noAccess`。
4. live MIB：`netsnmp-agent/src/mibgroup/vacm.rs`，实现 `SNMP-VIEW-BASED-ACM-MIB`（`1.3.6.1.6.3.16`）三个表为可 walk（可写表接 5.8）。
5. 配置：`snmpd.conf` 指令解析 `com2sec`/`com2sec6`/`group`/`view`/`access`/`access2`，映射到 `Vacm` 初始状态；`rocommunity`/`rwcommunity` 编译为等价的 `com2sec + group + access + view` 快捷（保持向后兼容）。
6. context 支持：默认 context 为 `""`；agent 暂不实现 context 名空间切换，但 `vacmContextTable` 可列出 `""`。

**验收目标**

- [x] 单测：`vacm::is_view_accessible` 对 10 步算法的覆盖（含 mask 位匹配、excluded 视图、`exact`/`prefix` context 匹配）。
- [x] 集成：`tests/` 新增 v2c 用户被 view 拒绝读取 `system` 的用例（返回 `noAccess` 或 varbind 为 `noSuchObject`）。
- [x] 集成：`snmpvacm` 经 SET 建视图后，相应 OID 变可读/不可读（依赖 5.8 完成可写表后补全用例）。
- [ ] 互操作：上游 `snmpvacm` 对本仓库 agent 操作成功；上游 agent 的 `snmpd.conf` 示例（含 `com2sec`/`access`）可被本仓库 `snmpd` 加载并行为一致。_（VACM 10 步算法 + `com2sec`/`group`/`view`/`access` 指令解析已单测覆盖；与上游 C 实机的互通未在 CI 中验证。）_
- [x] `snmpwalk` 在无权限视图下返回空而非泄露 OID。

---

#### Task 5.7　SET 4 阶段事务（reserve1/reserve2/commit/undo）— **L** — ✅ 完成

- **现状**：`handler.rs::MibHandler::set` 单步即提交；`registry.rs::process_set` 首个失败即回滚已提交的副作用（但已 `set` 成功的 handler 实际已写入，无法 undo）。
- **依赖**：无（被 5.8 依赖）。

**功能设计说明**

1. `handler.rs` 重构 `Mode` 为 `enum Mode { Get, GetNext, SetPhase(SetPhase) }`，新增：
   ```rust,ignore
   pub enum SetPhase { Reserve1, Reserve2, Commit, Undo, Cleanup }
   pub enum SetOutcome { Ok, Err(ErrorStatus), NeedCommit, NeedUndo }
   ```
   `MibHandler` 增加 `prepare_set(&self, ctx, oid, value) -> Result<Reservations>` 与 `commit(ctx)`/`undo(ctx)`；旧 `set` 保留为默认单步（兼容现有 handler）。
2. 上游 `baby_steps.c` 等价：默认 handler 在 Reserve1 做类型/范围校验、Reserve2 做资源预留、Commit 落盘、Undo 回滚。提供 `default_prepare`/`default_commit`/`default_undo` 便于标量 handler 一行接入。
3. `registry.rs::process_set` 改为：
   - **Reserve1**：遍历全部 varbind，任一非 `Ok` → 立即 Undo 已 Reserve 的（无副作用，仅丢弃 reservation），返回错误。
   - **Reserve2**：再遍历做互斥检查（如重复列、外键）。
   - **Commit**：逐个 commit；若 commit 失败（罕见）继续提交其余并最终 Undo 已提交的（best-effort，RFC 3416 §4.2.5 允许 `commitFailed`）。
   - 任一阶段失败，错误 index 指向首个出错的 varbind。
4. 事务上下文 `SetContext` 携带 reservation 槽（`HashMap<Oid, PendingValue>`），供 handler 跨阶段共享。

**验收目标**

- [x] 单测：构造两个相互约束的标量（A 设为 X 时 B 必须 ≤ Y），Reserve2 检测到冲突，返回 `inconsistentValue` 且 A/B 最终值不变（Undo 生效）。
- [x] 单测：单步默认 handler（未实现 prepare 的旧 handler）行为不变，向后兼容。
- [x] 集成：`tests/end_to_end.rs` 多 varbind SET，其中第二个非法，断言第一个未持久化（`get` 仍为旧值）。
- [x] `ScalarHandler::writable` 与 `MapHandler::writable` 接入 4 阶段（Reserve1 校验类型）。

---

#### Task 5.8　RowStatus 行创建语义 — **L** — ✅ 完成

- **现状**：`MapHandler::set` 对缺失行返回 `ErrorStatus::NoCreation`；无 `RowStatus` TC（SNMPv2-TC）状态机。`mgmt::row_status` 常量已定义但 agent 不处理。
- **依赖**：5.7（4 阶段事务）。

**功能设计说明**

1. 新增 `netsnmp-agent/src/row.rs`，定义 `RowStatus` 状态机（RFC 2579 §2 表）：
   - `active(1)` ↔ `notInService(2)`（SET 互转）
   - `notReady(3)` ↔ `notInService(2)`（依赖列是否齐全，由 5.17 的 DEFVAL/SIZE 判断或由 handler 显式声明必需列）
   - `createAndGo(4)`：原子创建并置 active；若必需列缺失 → `inconsistentName`
   - `createAndWait(5)`：创建并置 notInService/notReady
   - `destroy(6)`：删除行
2. `MapHandler`（或新 `TableHandler`）泛型化行值，支持注册 `row_status_column(u32)` 与 `required_columns(&[u32])`；SET RowStatus 列时驱动状态机，SET 其它列仅在 `active`/`notInService` 可写。
3. 与 5.7 协作：`createAndGo` 在 Reserve1 检查必需列，Reserve2 预占行，Commit 落库，Undo 删除预占行。
4. 配合 `ScalarHandler` 不变（标量无 RowStatus）。

**验收目标**

- [x] 单测：`createAndGo` 缺必需列 → `inconsistentName`；齐全 → 行出现且状态 `active`。
- [x] 单测：`destroy` 已存在行 → 行消失；后续 GET 该实例 → `noSuchInstance`。
- [x] 单测：在 `notReady` 状态 SET 非状态列 → `inconsistentValue`。
- [x] 集成：用 5.6 VACM 表做端到端 RowStatus 行创建（`snmpvacm createview` → agent 接受）。
- [x] 与 5.6 联调后，`snmpvacm` 全链路 create/delete 成功。

---

#### Task 5.9　表格助手工具箱 — **L** — ✅ 完成

- **现状**：仅 `ScalarHandler`/`MapHandler`/`FnHandler`。后续所有 MIB 模块（5.21/5.22/5.23/5.25/5.26）与 AgentX（5.18）、mib2c（5.32）都依赖富表格抽象。
- **依赖**：5.8（RowStatus）。

**功能设计说明**

1. 新模块 `netsnmp-agent/src/helpers/`（对照上游 `agent/helpers/`），逐个移植为 Rust trait + 实现：
   - `table/mod.rs`：`TableHandler { columns, rows }`，每行 `BTreeMap<u32, Value>` 按 index 排序；GET/GETNEXT/GETBULK 按 column-aware 方式遍历（避免当前 `FnHandler` 全表重排的开销）。
   - `table_dataset.rs`：`TableDataSet` 在 `TableHandler` 上加"列元数据"（SYNTAX/MAX-ACCESS/DEFVAL），供 `-Td` 与值校验（依赖 5.17）。
   - `table_iterator.rs`：把外部迭代器（`Iterator<Item=Row>`）适配为 handler，供动态数据（如 `/proc` 解析）。
   - `table_container.rs`：可插拔后端（`Vec`/`BTreeMap`/外部），便于 AgentX 子代理挂载。
   - `cache_handler.rs`：通用 TTL 缓存（把 `FnHandler` 的 900ms 缓存抽象为可复用 wrapper）。
   - `watcher.rs`：直接映射内存变量（上游 `watcher.c`，对标 `ScalarHandler` 但支持多字段 struct 偏移式访问）。
   - `row_merge.rs`：合并多行 GETBULK 请求（GETBULK 一次返回多行时按行重组）。
   - `bulk_to_next.rs`：把 GETBULK 翻译为多次 GETNEXT（agent 不原生支持 BULK 时用，本仓库 agent 已支持，故作为可选降级）。
   - `read_only.rs`：包装器，强制拒绝 SET。
   - `mode_end_call.rs`：在 SET 事务末尾调用回调（配合 5.7）。
2. 保持 `MibHandler` trait 不变，各助手实现该 trait，通过组合（`Arc<dyn MibHandler>`）而非继承扩展。
3. 文档：每个助手一个 doctest 示例，对照上游 helper 文档结构。

**验收目标**

- [x] 单测：`TableHandler` 对稀疏列（部分行缺某列）GETNEXT 跳到正确下一列而非 `noSuchInstance`。
- [x] 单测：`cache_handler` 在 TTL 内不重新调用 provider，过期后刷新。
- [x] doctest：每个助手至少一个可运行示例。
- [x] 迁移：`mibgroup/interfaces.rs` 用 `TableHandler` 重写后行为不变（现有 `tests/end_to_end.rs` 全绿），代码量下降。
- [x] 基准（可选）：大表（10k 行）walk 耗时较 `FnHandler` 重排版本下降。

---

#### Task 5.10　sysORTable 与框架 MIB 可 walk 对象 — **M** — ✅ 完成

- **现状**：`agent.rs` 内部维护 `engine_id/engine_boots/engine_time/usm_stats`，但**未注册为 MIB handler**，不可 walk。`system.rs` 无 sysORTable。
- **依赖**：无。

**功能设计说明**

1. `mibgroup/system.rs` 增加 `sysORTable`（`1.3.6.1.2.1.1.9.1`）handler：`sysORIndex/sysORID/sysORDescr/sysORUpTime`，由 agent 启动时各模块自报登记（提供 `Agent::register_sysOR(id, descr)`，对照上游 `register_sysORTable`）。
2. 新 `mibgroup/snmp_framework.rs`：SNMP-FRAMEWORK-MIB `snmpEngine` 组（`1.3.6.1.6.3.10.2.1`）—— `snmpEngineID`/`snmpEngineBoots`/`snmpEngineTime`/`snmpEngineMaxMessageSize`，值来自 `Agent::engine()`。
3. 新 `mibgroup/usm_stats.rs`：`usmStats`（`1.3.6.1.6.3.15.1.1`）五个计数器（`UnsupportedSecLevels/NotInTimeWindows/UnknownUserNames/UnknownEngineIDs/WrongDigests/DecryptionErrors`），把现有 `usm_stats: AtomicU32`（当前仅单计数器）拆分为六个独立 `AtomicU64`。
4. 新 `mibgroup/snmp_mpd.rs`：SNMP-MPD-MIB 计数器（可选）。
5. `register_system_mibs` 默认注册上述组（可通过 `SystemMibConfig` 关闭）。

**验收目标**

- [x] `snmpwalk -c public 127.0.0.1 1.3.6.1.6.3.10.2.1` 返回 4 个 snmpEngine 标量，`snmpEngineBoots` ≥ 1。
- [x] `snmpwalk ... 1.3.6.1.6.3.15.1.1` 返回 6 个 usmStats 计数器。
- [x] 触发一次未知用户的 v3 请求后，`snmpget ... usmStatsUnknownUserNames.0` 计数 +1。
- [x] `snmpwalk ... system` 包含 `sysORTable` 行，列出已登记模块。
- [x] 集成测试 `tests/end_to_end.rs` 新增用例。

### 优先级 P1 — 持久化与通知

---

#### Task 5.11　持久化存储 — **L** — ✅ 完成

- **现状**：所有可写标量（`sysContact`/`sysName`/`sysLocation`）存于 `RwLock` 内存，重启丢失；`snmpEngineBoots` 仅配置值；USM 用户不持久化。无 `snmp-store` 目录与 PERSISTENT 回调。
- **依赖**：无（被 5.6/5.8/5.27 依赖）。

**功能设计说明**

1. 新模块 `netsnmp-agent/src/persist.rs`（对照 `read_config.c` 的 PERSISTENT 机制）：
   - 持久目录：`SNMP_PERSISTENT_DIR`（默认 `/var/lib/snmp`，已有 `config/search.rs` 解析），每 agent 一个文件 `snmpd.conf`（运行态）+ `<engine_id>.persistence`。
   - `trait Persistable { fn key(&self) -> &str; fn snapshot(&self) -> Vec<Directive>; fn restore(&self, dirs: &[Directive]); }`，由 `ScalarHandler`/USM 用户表/VACM 表实现。
   - `Agent::schedule_persist(period)` 定期（默认 5min + 退出信号）调用 `SAVE-PERSISTENT`，序列化为 `Directive` 写文件。
   - 启动时 `READ-PERSISTENT`：经 `config/parse.rs` 读取并回放 `Directive` 到各 `Persistable`。
2. `snmpEngineBoots`：启动时读 `<engine_id>.boots`，+1 写回；崩溃恢复正确（文件存在但 agent 未正常退出 → boots 不 +1，仅正常退出才 +1，对照上游）。
3. USM 用户：`createUser`/`usmUserTable` SET 后持久化（依赖 5.10 可写表或直接持久化 `AgentConfig::users`）。
4. 信号处理：`SIGTERM`/`SIGINT` → 触发最终 SAVE 后退出（tokio signal）。

**验收目标**

- [x] 集成：SET `sysContact.0 = X` → 重启 agent → GET `sysContact.0` 仍为 X。
- [x] 集成：正常退出 3 次后 `snmpEngineBoots` = 初始值 + 3；kill -9 后不递增。
- [x] `createUser alice ...` 写入 `snmpd.conf` 后，删除该行重启，alice 仍可用（来自持久文件）。
- [x] 持久文件可被 `config/parse.rs` 往返解析。
- [x] 文档：`snmpd.conf` 注明 `persistentDir` 指令支持。

---

#### Task 5.12　通知发起方 + target/notification MIB — **XL** — ✅ 完成

- **现状**：agent **不主动发 trap**。客户端有 `send_trap`/`send_inform`；agent 有 `TrapReceiver`（被动收）。无 SNMP-TARGET-MIB / SNMP-NOTIFICATION-MIB。
- **依赖**：无（被 5.13/5.25 依赖）。

**功能设计说明**

1. 新模块 `netsnmp-agent/src/notify/mod.rs`（对照 `agent/agent_trap.c` + `target/` + `notification/`）：
   - `NotificationOriginator`：`send(&self, trap_oid, varbinds) -> Result<()>`，遍历 `snmpNotifyTable` 找匹配目标，按 `snmpTargetParamsEntry` 选 securityName/level/model，按 `snmpTargetAddrEntry` 选 transport + timeout，调 `netsnmp::Session`/`V3Session` 发送（TrapV2 或 Inform 按 `snmpNotifyType`）。
2. live MIB（依赖 5.8/5.9 可写，先内存只读也可）：
   - SNMP-TARGET-MIB（`1.3.6.1.6.3.12`）：`snmpTargetAddrTable` / `snmpTargetParamsTable`，handler 由 `NotifyTable` 后端驱动。
   - SNMP-NOTIFICATION-MIB（`1.3.6.1.6.3.13`）：`snmpNotifyTable` / `snmpNotifyFilterProfileTable`（filter 暂支持 OID 前缀匹配）。
3. 配置指令：`trapsink HOST [COMM] [PORT]`（v1）、`trap2sink`（v2c）、`informsink`（inform）、`trapsess`（v3 全参数），映射到 target 表 + notify 表。
4. agent 触发点：`Agent::send_notification(trap_oid, varbinds)`（公开 API），内部 `sysUpTime.0`/`snmpTrapOID.0` 自动前置（复用 `trap::build_notification`）。
5. 引擎：使用 agent 自身的权威 engine 参数作为 inform 的 contextEngineID。

**验收目标**

- [x] 集成：agent 启动时配 `trap2sink 127.0.0.1 public`，进程内 `TrapReceiver` 收到 `coldStart`。
- [x] 集成：`Agent::send_notification(customOid, [varbind])` 经 notify 表路由到多个目标（v2c + v3）。
- [x] `snmpwalk ... snmpNotifyTable` 返回已配置目标；SET `snmpNotifyRowStatus = destroy` 后该目标不再收到 trap（依赖 5.8）。
- [x] inform 模式：目标不在线时 agent 按 `snmpTargetAddrTimeout/RetryCount` 重试。
- [ ] 互操作：上游 `snmptrapd` 收到本仓库 agent 发的 v2c trap 与 v3 inform。_（agent 通知发起方 + 进程内 `TrapReceiver` 端到端已通过；与上游 C `snmptrapd` 的实机互通未在 CI 中验证。）_

---

#### Task 5.13　snmptrapd 增强 — **M** — ✅ 完成（sqlite 后端为可选扩展，未实现）

- **现状**：`trap/mod.rs` 仅在 `serve_on` 回调中打印通知并 ack inform。无格式化、无转发、无日志后端、无 NOTIFICATION-LOG-MIB。
- **依赖**：5.12（NOTIFICATION-LOG 联动）。

**功能设计说明**

1. `snmptrapd.rs` 与 `trap/mod.rs` 解耦输出后端：`trait TrapSink { fn log(&self, notif: &ReceivedNotification) -> Result<()>; }`，提供：
   - `StdoutSink`（默认，`tracing::info!`）
   - `FileSink`（`-F` 路径，带轮转）
   - `SyslogSink`（`syslog` crate，`-Os`/`-OF`）
   - `SqliteSink`（`rusqlite`，可选 feature `sql`，对照 `snmptrapd_sql.c`）
   - `HandleSink`：`traphandle OID CMD` → 对匹配 OID 执行子进程，stdin 喂 varbind（对照上游 `traphandle`）
2. `-F FORMAT`：格式串解析（`%Y/%m/%d` 时间、`%W` 主机名、`%v` varbind 列表、`%N` trap 名），由 `MibRegistry::format_oid` 解析 trap 名（依赖 5.2）。
3. 输出选项 `-o`/`-O`（stdout/file/syslog/sql）与格式族 `-F`、`-Le`（less）。
4. NOTIFICATION-LOG-MIB（`1.3.6.1.2.1.92`）：`nlmLogTable` 环形缓冲，可 walk（依赖 5.9 表格助手 + 5.12 注册）。
5. 转发：`forward COMMUNITY HOST` 把收到的 trap 再转发（对照上游 `forward`）。

**验收目标**

- [x] `-F "%Y-%m-%d %H:%M:%S %N: %v"` 输出格式符合预期（单测格式化器）。
- [x] `traphandle 1.3.6.1.6.3.1.1.5.1 /path/script`：收到 linkDown 时脚本被调用，stdin 收到 varbind 文本（集成测试用临时脚本）。
- [ ] sqlite 后端：表 `snmptrap` 有行（feature 开启时）。_（未实现：`sql` feature 未引入 `rusqlite` 依赖；`TrapSink` 抽象已就绪，sqlite 后端为后续可选扩展。）_
- [x] `snmpwalk` 到 snmptrapd 的 `nlmLogTable` 返回最近通知（依赖 5.12）。
- [x] `-Os` syslog 输出（CI 中跳过 syslog 实际写入，验证构造的日志行）。

### 优先级 P2 — 传输安全与传输域扩展

---

#### Task 5.14　RFC 6353 Transport Security Model（TSM）— **L** — ✅ 完成

- **现状**：`tls.rs` 仅安全通道（rustls 服务端证书认证），无 `securityModel=4` 消息处理、无 `tlstmCertToTSN` 证书→securityName 映射、无 mTLS。SNMPv3 消息在 TLS 通道内仍走 USM。
- **依赖**：5.6（部分 ACL 复用）。

**功能设计说明**

1. 新模块 `netsnmp/src/v3/tsm.rs`（对照 `snmplib/snmptsm.c`），实现 RFC 6353 §5：
   - `Tsm` securityModel（值 4），处理 `securityParameters`（TSM 的为空 OCTET STRING）。
   - securityName 来源：TLS 握手对端证书 SubjectAltName / Subject CN，经 `tlstmCertToTSN` 表映射（映射规则：`snmpTLSIdentity` / `dnsName` / `ipAddress` 等）。
2. agent/client：TLS 连接建立后，`Session`/`V3Session` 在 v3 消息里用 `securityModel=4`，`securityName` 取自证书而非 USM `msgUserName`。
3. mTLS：`TlsServer` 增加 `with_client_auth(Optional/Required)` 与 trust store；`TlsClient` 支持加载客户端证书。
4. live MIB（agent 端，依赖 5.9）：SNMP-TLS-TM-MIB（`1.3.6.1.6.3.15.1.x`）`tlstmCertToTSNTable` / `tlstmParamsTable`；SNMP-TSM-MIB 计数器。
5. 配置：`snmpd.conf` 的 `certSecName CERT MAP`、`tlstmCertToTSN` 指令。

**验收目标**

- [x] 集成：客户端带证书连 mTLS agent，`securityName` 来自 CN；无证书被拒（`tlsClientCertificateUnknown`）。
- [x] 集成：`snmpget -L tls ...`（带 `--cert`/`--privkey`）成功，agent 日志显示 mapped securityName。
- [x] `snmpwalk ... tlstmCertToTSNTable` 返回映射规则（依赖可写表 5.8）。
- [x] VACM（5.6）基于 TSM securityName 生效。
- [ ] 互操作：上游 `snmpd` + `snmpget -L` 与本仓库互通（证书链信任时）。_（mTLS 握手 + TSM securityName 映射已单测覆盖；与上游 C 实机的互通未在 CI 中验证。）_

---

#### Task 5.15　DTLS over UDP 传输 — **M** — 🟡 桩（URI 解析就绪，真实握手待引入 DTLS crate）

- **现状**：无 `snmpDTLSUDPDomain`。
- **依赖**：5.14（TSM 共用）。

**功能设计说明**

1. `netsnmp/src/dtls.rs`：基于 `tokio-rustls` 的 DTLS（或 `webrtc-dtls` / `rustls` DTLS 分支），实现 `DtlsTransport`（client）与 `DtlsServer`（agent）。
2. `Session::open_dtls`、`Agent::serve_dtls` 构造函数；BER 帧与 UDP 相同（datagram per PDU）。
3. 握手超时/重传按 DTLS 自身；cookie 防放大攻击（RFC 6347）。
4. 与 TSM（5.14）共用证书映射。

**验收目标**

- [ ] 集成：client↔agent DTLS loopback，GET 成功。_（未实现：`dtls.rs` 为带文档桩，`send`/`receive` 返回 `Error::Protocol`；待引入 DTLS crate 后补真实握手。）_
- [ ] 集成：未信任证书被拒（对齐 TLS 用例）。_（未实现：依赖 DTLS 真实握手，同上。）_
- [ ] mTLS over DTLS 用例。_（未实现：依赖 DTLS 真实握手，同上。）_
- [ ] `snmpget udp+dtls://...` 或 `--transport dtls` 选项。_（未实现：`parse_dtls_addr` URI 解析已就绪，但传输层为桩，故端到端不可用。）_

---

#### Task 5.16　Unix socket / Callback 传输 — **S** — ✅ 完成

- **现状**：无 `snmpUnixDomain` 与 `snmpCallbackDomain`。
- **依赖**：无。

**功能设计说明**

1. `netsnmp/src/unix_transport.rs`：`UnixTransport`（基于 `tokio::net::UnixStream`），BER `SEQUENCE` 帧同 TCP；`Session::open_unix(path)`、`Agent::serve_unix(path)`。
2. `netsnmp/src/callback_transport.rs`：`CallbackTransport` 进程内 `mpsc::channel<Bytes>`，实现 `Transport` trait（已为 mock 设计过，正式化为公共类型），用于测试与 agent 内部子模块通信。
3. 地址表示：`unix:/path/to/sock`、`callback:NAME`（对照上游 transport URI）。

**验收目标**

- [x] 集成：client↔agent 经 Unix socket GET 成功。
- [x] `CallbackTransport` 单测：双向消息往返。
- [x] `Transport` trait 不需改签名即可接入（验证抽象稳定）。
- [x] snmpd 支持 `agentaddress unix:/var/run/snmpd.sock`。

### 优先级 P2 — SMI 解析增强

---

#### Task 5.17　SMI 语义解析增强 — **L** — ✅ 完成

- **现状**：`smi/parse.rs` 仅提取 OID 赋值与 INTEGER 枚举。TEXTUAL-CONVENTION、范围/SIZE 约束、DEFVAL、INDEX、MODULE-COMPLIANCE、OBJECT-GROUP 全缺。
- **依赖**：被 5.2（`-Td`/`-Tp`）、5.32（mib2c）、agent 值校验依赖。

**功能设计说明**

1. `smi/parse.rs` 扩展 `RawDef` 为结构化对象定义：
   ```rust,ignore
   pub struct ObjectDef {
       pub name, pub oid: Oid,
       pub syntax: Syntax,          // 基础类型 / TC 引用 / SEQUENCE
       pub units: Option<String>,
       pub max_access: Access,       // not-accessible/read-only/...
       pub status: Status,           // current/deprecated/obsolete
       pub description: Option<String>,
       pub reference: Option<String>,
       pub index: Option<Index>,     // {IMPLIED ident | ident...} / AUGMENTS
       pub defval: Option<Value>,
       pub enums: Vec<(i64,String)>,
   }
   pub enum Syntax { Base(BaseType), Tc(String), Sequence(Vec<(String, Syntax)>) }
   pub struct TextualConvention { pub name, pub base: Syntax, pub display_hint: Option<String>, pub status, pub description, pub refs }
   pub struct Constraint { pub ranges: Vec<(Option<i64>, Option<i64>)>, pub sizes: Vec<(usize, usize)> }
   ```
2. 解析：
   - OBJECT-TYPE 完整语法（`SYNTAX / UNITS / MAX-ACCESS / STATUS / DESCRIPTION "..." / INDEX / DEFVAL { ... }`）。
   - TEXTUAL-CONVENTION 宏体（`DISPLAY-HINT "255a"` 等）。
   - OBJECT-IDENTITY / NOTIFICATION-TYPE 的描述字段。
   - MODULE-COMPLIANCE：提取 `MANDATORY-GROUPS`、`GROUP`、`OBJECT … SYNTAX … MIN-ACCESS`，构建合规对象图。
   - OBJECT-GROUP / NOTIFICATION-GROUP：展开成员 OID。
   - INDEX：`IMPLIED` 修饰与 `AUGMENTS { entry }` 解析（用于 5.8 必需列推断）。
3. `smi/resolve.rs` 把 TC 引用解析为展开后的 `Syntax`（含约束合并）。
4. `MibRegistry` 增加 `object_def(oid) -> Option<&ObjectDef>`、`textual_convention(name)`、`is_writable(oid)`、`validate_value(oid, &Value) -> Result<(), ConstraintError>`。
5. 性能：完整解析 mibs/（~94 文件）耗时在可接受范围（<2s）；不阻塞当前 OID-only 路径。

**验收目标**

- [x] 单测：解析 IF-MIB，`ifAdminStatus` 的 SYNTAX 含枚举 up(1)/down(2)/testing(3)，MAX-ACCESS read-write。
- [x] 单测：`InetAddress`（INET-ADDRESS-MIB TC）的 DISPLAY-HINT 解析正确。
- [x] 单测：`validate_value` 对 SIZE 越界 OctetString 报错。
- [x] `snmptranslate -Td ifIndex` 显示完整定义（联动 5.2）。
- [x] agent 端 SET 前用 `validate_value` 校验类型/范围（联动 5.7 Reserve1）。
- [x] 性能：`MibRegistry::load_dir("./mibs")` 含语义解析仍 <2s。

### 优先级 P3 — Master/Subagent 与 Proxy

---

#### Task 5.18　AgentX 协议（RFC 2741）— **XL** — ✅ 完成

- **现状**：无 master/subagent。agent 为单进程扁平。
- **依赖**：5.9（表格助手，子代理挂载用）。

**功能设计说明**

1. 新 crate 子模块 `netsnmp-agent/src/agentx/`：
   - `protocol.rs`：AgentX PDU 编解码（RFC 2741 §6），PDU 类型 Open/Close/Register/Unregister/Get/GetNext/GetBulk/Set/Undo/Cleanup/Notify/AddAgentCaps/RemoveAgentCaps/Response，头 `version(1)/type/flags/sessionid/transactionid/subid/uptime(非标准)/timeout`。
   - `master.rs`：master agent，监听 Unix/TCP，管理 subagent 连接与子树注册表，把外部 SNMP 请求翻译为 AgentX 请求转发给注册子代理，聚合 Response；处理子代理崩溃的子树回收。
   - `subagent.rs`：subagent 客户端，连 master，`Register` 子树，响应 Get/Set；提供 `Subagent` builder（`register_handler(oid, handler)`）。
   - `transport.rs`：`AgentXTransport`（Unix stream + TCP）。
2. `Agent` 增加 `agentx_master` 模式：`Agent::serve_agentx(path)` 把 `Registry` 与 AgentX 子树合并分发（先查本地，再查子代理注册表）。
3. AGENTX-MIB（`1.3.6.1.4.1.6.1.x`，依赖 5.9）作为 live 对象暴露 master/subagent 状态。
4. 配置：`master agentx`、`agentXSocket PATH`、`agentxPingInterval`。
5. `agentxtrap`（apps）发送 AgentX Notify PDU。

**验收目标**

- [x] 单测：AgentX PDU 往返字节匹配 RFC 2741 示例。
- [x] 集成：subagent 注册 `1.3.6.1.4.1.9999`，外部 `snmpget` 该子树经 master 转发到 subagent 返回值。
- [x] 集成：subagent 断开后，其子树 GET 返回 `noSuchObject`（回收）。
- [ ] 互操作：本仓库 subagent 连上游 snmpd（master 模式），子树可被上游 `snmpget`；反向（上游 subagent 连本仓库 master）亦然。_（AgentX PDU 往返 + master/subagent 转发/回收已单测覆盖；与上游 C 实机的互通未在 CI 中验证。）_
- [x] `agentxtrap` 经 master 发出通知到 SNMP 管理站。

---

#### Task 5.19　Proxy forwarder（RFC 3413）— **M** — ✅ 完成

- **现状**：无 `proxy` 指令、无 SNMP-PROXY-MIB、无跨代理转发。
- **依赖**：无。

**功能设计说明**

1. `netsnmp-agent/src/proxy.rs`：`ProxyForwarder` handler，root 为配置的子树前缀；收到 GET/GETNEXT/GETBULK/SET 时，按 `snmpTargetAddrEntry` 找到目标 agent，用内部 `Session`/`V3Session` 转发，把响应 varbind 返回（OID 可选重写前缀）。
2. 配置：`proxy [-Cn CONTEXT] COMMUNITY HOST [OID]`（上游语法），映射到 proxy 子树注册 + target 条目。
3. context：支持 `proxy -Cn ctx ...`，转发时 contextEngineID 可重写（RFC 3413 §1）。
4. 与 5.12 target 表协作：复用 `snmpTargetAddrEntry` 作为目标描述。

**验收目标**

- [x] 集成：agent A 配 `proxy public 127.0.0.1:2161 1.3.6.1.4.1.9999`，agent B 服务该子树；`snmpget` 到 A 命中 B 的值。
- [x] 集成：GETNEXT 经 proxy 正确翻页。
- [x] v3 proxy：A↔B 间用 USM authPriv。
- [x] 子树冲突检测：proxy 子树与本地注册重叠时给出告警。

---

#### Task 5.20　SMUX（RFC 1227）— **M** — ✅ 完成

- **现状**：无 SMUX 协议与 BGP/OSPF/RIP MIB 委托。
- **依赖**：无。

**功能设计说明**

1. `netsnmp-agent/src/smux.rs`：SMUX peer 协议（SMUX_OPEN/REGISTER/GET-REQUEST/RESPONSE/CLOSE），作为 agent 的可挂载后端；peer（如 Quagga/FRR）注册子树，agent 转发 GET/GETNEXT。
2. 配置：`smuxpeer PASSWORD OID`、`smuxsocket`。
3. SMUX-MIB（`1.3.6.1.2.1.20`）live 对象。

**验收目标**

- [x] 单测：SMUX PDU 编解码。
- [x] 集成：mock SMUX peer 注册子树，`snmpget` 经 agent 转发返回值（无真实路由守护时用 mock）。
- [x] 文档：注明 SMUX 主要为历史兼容，建议新部署用 AgentX（5.18）。

### 优先级 P3 — MIB 模块长尾

---

#### Task 5.21　mibII 核心 MIB 模块 — **L** — ✅ 完成

- **现状**：无 TCP/UDP/IP/ICMP/at/ipv6/route/snmp_mib/setSerialNo。`snmpnetstat`/`snmpstatus` 因此依赖**外部** agent 提供这些对象。
- **依赖**：5.9（表格助手）。

**功能设计说明**

1. 新模块 `netsnmp-agent/src/mibgroup/{tcp,udp,ip,icmp,at,ipv6,route,snmp_mib}.rs`，全部基于 `sysinfo` + 平台特定（Linux `/proc/net/*`、跨平台兜底）：
   - TCP-MIB（`1.3.6.1.2.1.6`）：`tcpConnTable`（含状态/本地/远程地址端口）、`tcp` 标量（`tcpInSegs` 等）；HC 列 `tcpConnectionTable`。
   - UDP-MIB（`1.3.6.1.2.1.7`）：`udpTable`、`udpEndpointTable`、标量。
   - IP-MIB（`1.3.6.1.2.1.4`）：`ip`、`ipAddrTable`、`ipNetToMediaTable`、`ipSystemStatsTable`（HC）。
   - ICMP-MIB / IPV6-ICMP-MIB。
   - at 表（`1.3.6.1.2.1.3.1`）：ARP 表。
   - route：`ipRouteTable` + `inetCidrRouteTable`（IP-FORWARD-MIB）。
   - snmp_mib（`1.3.6.1.2.1.11`）：`snmpInPkts` 等 30 个标量（agent 需维护这些计数器，每次收发报文递增）。
   - setSerialNo（`1.3.6.1.6.3.1.1.6.1`）：单标量，SET 递增。
2. `register_system_mibs` 扩展为 `register_mib2_mibs`，可选开关。
3. snmp 计数器：在 `agent.rs::handle_datagram` 注入钩子，递增 `snmpInPkts/snmpInBadVersions/snmpInASNParseErrs` 等。

**验收目标**

- [x] `snmpwalk ... tcp` 返回连接表；与系统 `ss -t` / `netstat` 数量一致（允许多寡差异，主键一致）。
- [x] `snmpnetstat -p tcp`（联动 5.28）输出连接列表。
- [x] `snmpget ... ipInReceives.0` 返回计数；重复请求值递增。
- [x] `snmpwalk ... 1.3.6.1.2.1.11`（snmp_mib）返回 30 个标量。
- [x] 集成测试覆盖至少 TCP/UDP 表。

---

#### Task 5.22　HOST-RESOURCES-MIB 补全 — **M** — ✅ 完成

- **现状**：缺 hrPrinterTable、hrDiskStorageTable、hrPartitionTable、hrNetworkTable、hrSWInstalledTable、hrFSLastFullBackupDate；hrSWRunStatus 不可写；hrFSType 恒 Other。
- **依赖**：5.8（部分，hrSWRunStatus 写、hrStorage 与行创建无关）。

**功能设计说明**

1. `mibgroup/host.rs` 扩展 `HostCollector`（`collector.rs`）采集：打印机（跨平台多为空表）、磁盘存储/分区（Linux `/proc/partitions` 或 sysinfo）、网络设备关联、已安装软件（包管理器查询，可选）、文件系统备份时间（无源则 `unknown(2)`）。
2. hrFSType：按文件系统 magic（`statvfs`/`statfs`）映射 `hrFSBerkeleyFFS/hrFSLinuxExt2/hrFSFAT32/...`。
3. hrSWRunStatus 写：`running(1)/runnable(2)/notRunnable(3)/invalid(4)`，SET `invalid` 触发发信号终止进程（需权限检查 + VACM）。
4. 跨平台兜底：不支持平台返回合理空表，不 panic。

**验收目标**

- [x] `snmpwalk ... hrFS` 中 `hrFSType` 反映真实文件系统类型（ext4/xfs/ntfs）。
- [x] `snmpset ... hrSWRunStatus.PID i 4` 后进程退出（需权限，集成测试用自身子进程）。
- [x] `snmpwalk ... hrDiskStorageTable` / `hrPartitionTable` 返回磁盘/分区（Linux 上）。
- [x] 其它平台不 panic（CI 矩阵覆盖）。

---

#### Task 5.23　UCD-SNMP-MIB 补全 + extend/pass — **L** — ✅ 完成

- **现状**：缺 systemStats 全列、extTable/exec、prTable、file、version、dlmod、snmperrs、mrTable、logMatch、NET-SNMP-EXTEND-MIB、pass/pass_persist。
- **依赖**：5.9（表格助手）。

**功能设计说明**

1. `mibgroup/ucd.rs` 扩展：
   - systemStats（`1.3.6.1.4.1.2021.11`）：`ssCpuRawUser/Nice/System/Idle/Wait/Kernel/Interrupt`、`ssIORawReceived/Sent`、`ssInterrupts/RawInterrupts`、`ssRawContexts`、`ssRawSwaps`、`ssRawInterrupts`，基于 sysinfo + Linux `/proc/stat`。
   - extTable（`1.3.6.1.4.1.2021.8`）/ `exec` 指令：`exec NAME CMD ARGS...`，运行子进程采集 stdout 行（MIB 暴露 `extOutput1` 等）。
   - prTable（`1.3.6.1.4.1.2021.2`）：`proc NAME [MAX [MIN]]`，进程存在性检查。
   - file（`1.3.6.1.4.1.2021.3`）：`file NAME PATH`，文件大小/校验/存在性。
   - version 组（`1.3.6.1.4.1.2021.1`）：`versiontag/versioncdate/versionconfigure`。
   - dlmod：动态加载（Rust 中对应"插件 feature"，非 dlopen，或仅记录不支持）。
   - logMatch：`logmatch NAME PATH OFFSET REGEX`，扫描日志计数匹配。
   - mrTable：内存池。
2. NET-SNMP-EXTEND-MIB（`1.3.6.1.4.1.8072.1.3.2`）：`extend NAME CMD ARGS`（exec 的现代版，支持 exit code/stdout/stderr 分列），handler 调子进程。
3. pass / pass_persist（NET-SNMP-PASS-MIB）：子树委托给外部脚本（pass：每次调用；pass_persist：长连接，stdin 命令往返）。`pass PIVOT OID CMD`。

**验收目标**

- [x] `snmpwalk ... 1.3.6.1.4.1.2021.11` 返回全部 ssCpuRaw/ssIO 列。
- [x] `exec diskusage df -h` 后 `snmpget ... extOutput.1` 返回 df 第一行。
- [x] `extend pingcheck /bin/ping -c1 127.0.0.1` 后 `snmpget ... nsExtendOutput1Line."pingcheck"` 返回 ping 结果。
- [x] `pass -p 1.3.6.1.4.1.9999 /path/script` 后 walk 该子树返回脚本输出。
- [x] pass_persist：多次 GET 复用同一子进程（脚本保持运行）。
- [x] 集成测试覆盖 exec/extend/pass 各一。

---

#### Task 5.24　hardware/ 抽象层（cpu/fsys/memory/sensors）— **M** — ✅ 完成

- **现状**：`collector.rs` 直接用 sysinfo 采集，散落在多处；无统一硬件抽象；无 LM-SENSORS-MIB。
- **依赖**：无。

**功能设计说明**

1. `netsnmp-agent/src/hardware/{mod,cpu,fsys,memory,sensors}.rs`（对照上游 `agent/mibgroup/hardware/`），定义 `trait CpuAccess/FsysAccess/MemoryAccess/SensorAccess`，默认实现用 sysinfo，平台特定实现可 feature 切换（Linux `/sys/class/hwmon`）。
2. LM-SENSORS-MIB（`1.3.6.1.4.1.2021.13`）：`lmTempSensorsTable`/`lmFanSensorsTable`/`lmVoltSensorsTable`，从 `hwmon` 读温度/风扇/电压。
3. 重构 `collector.rs` 为对 hardware 层的薄封装，去重逻辑。

**验收目标**

- [x] Linux CI：`snmpwalk ... lmTempSensorsTable` 返回至少一个温度（如无传感器则空表，不报错）。
- [x] 重构后 `tests/end_to_end.rs` 全绿（host/ucd 输出不变）。
- [x] trait 可被测试 mock（注入假数据）。

---

#### Task 5.25　DISMAN 分布式管理 MIB 全套 — **XL** — ✅ 完成

- **现状**：DISMAN 全套缺失。
- **依赖**：5.9（表格助手）、5.12（事件通知）、5.31（alarm 定时，调度用）。

**功能设计说明**

1. `netsnmp-agent/src/disman/{event,schedule,expr,ping,traceroute,nslookup}.rs`：
   - DISMAN-EVENT-MIB（`1.3.6.1.2.1.88`）：`mteTriggerTable`（存在/布尔/阈值/增量触发）、`mteEventTable`（通知/Set）、`mteObjectsTable`（通知附加 varbind）。后台轮询触发器（依赖 5.31 alarm），命中时经 5.12 发通知。
   - DISMAN-SCHEDULE-MIB（`1.3.6.1.2.1.63`）：`schedTable`，按 cron/周期触发 Set 或通知。
   - DISMAN-EXPRESSION-MIB（`1.3.6.1.2.1.90`）：`expExpressionTable`，定义算式（`$ifInOctets.1 * 8`），按需计算。
   - DISMAN-PING / TRACEROUTE / NSLOOKUP-MIB：`pingResultsTable` / `traceRouteResultsTable` / `lookupResultsTable`，用 `tokio::net` + `hickory-dns` 实现，结果表按测试编号索引。
2. 全部为可写表（RowStatus，依赖 5.8），配置 `agentSecName`、`iquery` 内部查询身份。
3. 内部查询（`iquery`）：agent 以自身身份查询自身对象（对照 `utilities/iquery.c`）。

**验收目标**

- [x] 集成：创建 `mteTrigger` 监控某 Counter，超过阈值时 agent 发 trap（联动 5.12 接收）。
- [x] 集成：`schedTable` 定时 Set 一个标量，按时触发。
- [x] 集成：`pingResultsTable` 创建行后出现 ping 结果。
- [x] DISMAN-EXPRESSION：GET `expExpression` 实例返回计算值。
- [ ] 互操作：上游配置示例可在本仓库 agent 复现。_（DISMAN 各表结构与触发逻辑已单测覆盖；上游配置文件的实机复现未在 CI 中验证。）_

---

#### Task 5.26　协议杂项 MIB — **M** — ✅ 完成

- **现状**：EtherLike/BRIDGE/SCTP/TUNNEL/RMON/MTA 全缺。
- **依赖**：5.9。

**功能设计说明**

1. `netsnmp-agent/src/mibgroup/{etherlike,bridge,sctp,tunnel,rmon,mta}.rs`：
   - EtherLike-MIB（`1.3.6.1.2.1.10.7`）：`dot3StatsTable`，与 ifIndex 关联，从 sysinfo/平台统计取值（多数平台无源则填 0）。
   - BRIDGE-MIB（`1.3.6.1.2.1.17`）：`dot1dBasePortTable`/`dot1dTpFdbTable`，依赖网桥/交换能力，多数主机空表。
   - SCTP-MIB（`1.3.6.1.2.1.105`）：SCTP 统计（如无则 0）。
   - TUNNEL-MIB（`1.3.6.1.2.1.10.131`）：隧道接口表。
   - RMON-MIB（`1.3.6.1.2.1.16`）：远程监控，按需实现 `alarmTable`/`eventTable`（与 DISMAN 重叠，取其一）。
   - MTA-MIB（`1.3.6.1.2.1.28`）：邮件传输代理统计。
2. 优先级低于核心 mibII，作为广度补全；不支持平台返回空表。

**验收目标**

- [x] `snmpwalk ... dot3StatsTable` 不报错（Linux 上可能仅 ifIndex 关联行）。
- [x] 各 MIB at minimum 返回正确结构（即便值为 0/空）。
- [x] 单测覆盖 OID 注册范围与列编号。

---

#### Task 5.27　NET-SNMP 自管理 MIB — **M** — ✅ 完成

- **现状**：NET-SNMP-AGENT-MIB / NET-SNMP-MIB 缺。
- **依赖**：5.6（nsVacm）、5.11（持久化）。

**功能设计说明**

1. `netsnmp-agent/src/mibgroup/netsnmp_{agent,system}.rs`：
   - NET-SNMP-AGENT-MIB（`1.3.6.1.4.1.8072.1`）：`nsCache`（各模块缓存 TTL 读写）、`nsDebug`（debug 输出级别）、`nsLogging`（日志级别/目标）、`nsModuleTable`（已注册模块清单，联动 sysORTable）、`nsTransactionTable`（当前 SET 事务，联动 5.7）、`nsVacmAccessTable`（VACM 扩展，联动 5.6）。
   - NET-SNMP-MIB（`1.3.6.1.4.1.8072.1.x`）：`nsCacheEnabled`、`nsConfigDebug`、agent 版本信息。
2. nsCache：把 5.9 `cache_handler` 的 TTL 经此表暴露并可 SET 调整。

**验收目标**

- [x] `snmpwalk ... 1.3.6.1.4.1.8072.1` 返回 nsCache/nsModule 行。
- [x] SET `nsCacheTimeout.MODULE = 30` 后该模块缓存 TTL 改变（联动 5.9 验证）。
- [x] `nsModuleTable` 列出所有已注册 MibHandler。
- [x] `nsTransactionTable` 在 SET 进行时出现一行（联动 5.7，时序测试）。

### 优先级 P3 — 工具增强

---

#### Task 5.28　snmpnetstat 完整模式 — **M** — ✅ 完成

- **现状**：`snmpnetstat.rs` 仅 `-p tcp|udp|all`，walk tcpConnTable/udpTable。
- **依赖**：5.21（接口/路由/统计对象）。

**功能设计说明**

1. 扩展 `-p` 枚举与新增标志（对照上游 `apps/snmpnetstat/`）：
   - `-i`：`ifTable` 接口表（名/MTU/状态/速率）。
   - `-r`：`ipRouteTable` / `inetCidrRouteTable` 路由表。
   - `-a`：全部套接字（tcp+udp，含 LISTEN）。
   - `-s`：各协议统计（ip/icmp/tcp/udp 标量分组）。
   - `-n`：数字（不反向解析 IP/端口名）。
   - `-P PROTO`：过滤协议。
2. 输出格式对齐 `netstat`（列宽/表头）。

**验收目标**

- [x] `snmpnetstat -i` 输出含 lo/eth0。
- [x] `snmpnetstat -r` 输出含默认路由。
- [x] `snmpnetstat -s` 分 IP/TCP/UDP 段。
- [x] `snmpnetstat -an` 全数字。
- [x] 集成测试 `tests/cli_tables.rs` 扩展。

---

#### Task 5.29　snmpps 增强 — **S** — ✅ 完成

- **现状**：`snmpps.rs` 仅列 hrSWRunTable（名/路径/类型/状态）。
- **依赖**：5.22（hrSWRunPerf 的 CPU/内存列）。

**功能设计说明**

1. 增加 `-c`（完整命令行，hrSWRunPath + 参数）、`-w`（宽输出，含 hrSWRunPerfCPU/Mem）、per-PID 查询（`snmpps HOST PID`）。
2. 输出对齐 `ps` 风格（PID/USER/CR/VSZ/RSS/COMMAND，受 MIB 可得性限制）。

**验收目标**

- [x] `snmpps -c` 显示完整命令行。
- [x] `snmpps -w` 含 CPU%/MEM%。
- [x] `snmpps HOST 1234` 仅显示该 PID。

---

#### Task 5.30　snmpd.conf 完整指令支持 — **M** — ✅ 完成

- **现状**：`settings.rs::SnmpdSettings` 仅解析 `rocommunity/rwcommunity/sysLocation/sysContact/agentAddress/createUser`。
- **依赖**：5.6（VACM 指令）、5.12（trap sink 指令）、5.19（proxy）、5.23（exec/extend/pass）。

**功能设计说明**

1. 扩展 `SnmpdSettings` 解析：
   - `com2sec`/`com2sec6`/`group`/`view`/`access`/`access2`（VACM，联动 5.6）。
   - `trapsink`/`trap2sink`/`informsink`/`trapsess`（联动 5.12）。
   - `proxy`（联动 5.19）。
   - `agentaddress`（多地址，逗号或空格分隔，含 `tcp:`/`unix:`）。
   - `exec`/`extend`/`pass`/`pass_persist`/`disk`/`proc`/`load`/`file`/`logmatch`（联动 5.23/5.24）。
   - `master agentx`/`agentXSocket`（联动 5.18）。
   - `smuxpeer`/`smuxsocket`（5.20）。
   - `iquery`/`agentSecName`（5.25 内部查询身份）。
2. 每条指令映射到 `AgentConfig`/`Vacm`/`Notify`/`Proxy` 等结构，构建时注入 `Agent::new`。

**验收目标**

- [x] 单测：上游 `snmpd.conf.example` 全量解析不报错（未知指令跳过并 warn）。
- [x] 集成：含 `com2sec`/`group`/`access`/`view` 的 conf 启动后 VACM 生效（联动 5.6）。
- [x] 集成：`trapsink` 指令启动后 agent 启动发 coldStart（联动 5.12）。
- [x] 多 `agentaddress` 同时监听 UDP + Unix。

### 优先级 P4 — 周边与生态

---

#### Task 5.31　snmpalarm / callback 异步框架 — **M** — ✅ 完成

- **现状**：无 `snmp_alarm.c` 定时事件、无 `callback.c` 异步分发。agent 内部模块（DISMAN 调度、nsCache 刷新）目前各自 tokio task。
- **依赖**：无（被 5.25 依赖）。

**功能设计说明**

1. `netsnmp/src/alarm.rs`：`AlarmRegistry`，注册 `(interval, callback)`，提供 `async fn run()` 在 tokio runtime 驱动；`add_alarm(duration, cb)` / `remove_alarm(id)`。对照 `snmp_alarm.c` API 语义（含 `SA_REPEAT`/`SA_EXECUTE_ONCE`）。
2. `netsnmp-agent/src/callback.rs`：`CallbackBus<T>`，模块间发布/订阅（master↔subagent、触发器→通知），基于 `tokio::sync::broadcast`。
3. agent 集成：`Agent::with_alarms()` 内置 alarm registry；`serve_forever` 同时驱动。
4. 与 tokio 原生 task 区分：保留 SNMP 语义的优先级与命名（便于对照上游）。

**验收目标**

- [x] 单测：周期 alarm 按间隔触发次数正确；一次性 alarm 触发一次后移除。
- [x] 单测：CallbackBus 多订阅者收到同一事件。
- [x] 集成：5.25 的 schedTable 经 alarm 触发（联动验证）。

---

#### Task 5.32　mib2c 代码生成器 — **M** — ✅ 完成

- **现状**：无 `local/mib2c`。SMI 解析（5.17）+ 表格助手（5.9）就绪后可做。
- **依赖**：5.9、5.17。

**功能设计说明**

1. 新 crate `netsnmp-mib2c`（或 `netsnmp-apps` 子命令），输入 MIB 文件 + 节点名，输出 Rust handler 骨架：
   - 标量：基于 `ScalarHandler`，含 SYNTAX 校验。
   - 表格：基于 `TableHandler`/`TableDataSet`，含列元数据、INDEX、RowStatus。
   - 通知：`Notification` 定义 + 注册。
2. 模板：内置 `scalar.rs.j2`/`table.rs.j2`（用 `askama` 或简单字符串替换），对照上游 `mib2c/*.c.conf`。
3. CLI：`mib2c [-c config] NODE`，输出到 stdout 或 `-o DIR`。

**验收目标**

- [x] 对 IF-MIB `ifTable` 运行，生成的 `.rs` 可编译并注册，walk 返回结构正确的空/默认表。
- [x] 生成代码通过 `cargo fmt` 与 `clippy -D warnings`。
- [x] 文档：与上游 `mib2c` 用法对照表。

---

#### Task 5.33　default_store 运行时开关 — **S** — ✅ 完成

- **现状**：无 `default_store.c` 的 DS 命名开关（DS_LIBRARY_*/DS_APPLICATION_*/DS_AGENT_*）。
- **依赖**：无。

**功能设计说明**

1. `netsnmp/src/default_store.rs`：`DefaultStore`（`RwLock<HashMap<(DsCategory, i32), DsValue>>`），`set_bool/int/string`、`get_*`、`toggle`，预定义常量（对照 `default_store.h`）。
2. 配置：`snmp.conf`/`snmpd.conf` 中 `overrideTYPE NAME VALUE`（对照上游 `override`）。
3. 客户端/agent 读取 DS 决定行为（如 `DS_AGENT_NO_ROOT_ACCESS`、`DS_LIB_PRINT_NUMERIC_OIDS` → snmptranslate 默认 `-On`）。

**验收目标**

- [x] 单测：set/get 往返；类别隔离。
- [x] `defVersion` 等现有配置迁移到 DS（行为不变，回归测试）。
- [x] `override` 指令生效。

---

#### Task 5.34　共享 UDP 套接字 + systemd socket 激活 — **S** — ✅ 完成

- **现状**：每个 `Session` 独立 socket；无 `snmpUDPsharedDomain`；无 sd-daemon 集成。
- **依赖**：无。

**功能设计说明**

1. `netsnmp/src/transport.rs`：`UdpSharedTransport`，多 `Session` 复用一个 bound socket（请求/响应按 request-id 路由），降低大流量场景的 fd 消耗。
2. `sd-daemon`：agent 启动时检测 `LISTEN_FDS`（`libsystemd` 或手解析环境变量），继承预绑 socket（SD_LISTEN_FDS_START），便于 systemd 端口管理与无特权重启。
3. 配置：`snmpd` 支持 `--sd` 标志。

**验收目标**

- [x] 集成：两个 `Session` 用 shared socket 并发 GET，响应按 request-id 正确返回。
- [x] 集成（有 systemd 环境）：`systemd-socket-activate -l 1161 ./snmpd` 继承 fd 并服务。
- [x] 单测：request-id 路由分发正确。

---

## 6. 依赖关系速查图

```
5.9 表格助手 ──┬─► 5.6  VACM
              ├─► 5.18 AgentX
              ├─► 5.21 mibII 核心
              ├─► 5.23 UCD/extend/pass
              ├─► 5.25 DISMAN
              └─► 5.32 mib2c

5.7 SET 4 阶段 ─► 5.8 RowStatus ─► 5.6 VACM（可写表）
                              └─► 5.22 HOST-RESOURCES 补全

5.12 通知发起方 ─► 5.13 snmptrapd 增强
                └─► 5.25 DISMAN（事件通知）

5.14 TSM ─► 5.15 DTLS
5.17 SMI 增强 ─► 5.2  snmptranslate 全模式
                └─► 5.32 mib2c
5.6 VACM ┬─► 5.27 NET-SNMP 自管理
        └─► 5.30 snmpd.conf 完整指令（还需 5.12/5.19/5.23）
```

---

## 7. 建议路线

> **实现状态（截至本次审计）**：上述 34 项任务中 **33 项已完成（✅）**，仅 **5.15 DTLS** 为带文档桩（🟡，待引入 DTLS crate）。`cargo build --workspace --all-targets` 零警告，`cargo test --workspace` **675 项测试全绿**。
>
> 原路线图（按优先级分组）保留如下，供追溯依赖实现顺序：
1. **短期（P0，快速补全小缺口）**：5.1 v1 trap、5.4 encode_keychange、5.3 snmpusm/vacm 操作、5.10 框架 MIB 可 walk、5.16 Unix/Callback 传输 — ✅ 全部完成。
2. **中期（P1，agent 生产化）**：5.6 VACM、5.7 SET 事务、5.8 RowStatus、5.9 表格助手、5.11 持久化、5.12 通知发起方 — ✅ 全部完成。
3. **中长期（P2，广度）**：5.21 mibII 核心、5.22/5.23 host/ucd 补全、5.14 TSM、5.17 SMI 增强、5.28/5.29 工具增强 — ✅ 完成；5.15 DTLS 为桩。
4. **长期（P3，长尾与生态）**：5.18 AgentX、5.19 Proxy、5.20 SMUX、5.25 DISMAN、5.26 协议杂项 MIB、5.31 alarm/callback、5.32 mib2c — ✅ 全部完成。

> 注：**Perl/Python 绑定、mib2c 的完整 C 模板生态、snmptrapd 内嵌脚本/sqlite 后端**被 README 明确列为 out-of-scope 或为可选扩展，不在本清单核心目标内。
