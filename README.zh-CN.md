# dnsflt

**English** | [简体中文](README.zh-CN.md)

一个单进程的 Windows CLI DNS 拦截器。`dnsflt` 通过 WinDivert 捕获本机所有发往
53 端口的 DNS 查询，交给指定的上游解析器处理，再把应答包注入回协议栈——
应用程序完全察觉不到应答并非来自它当初寻址的服务器。

行为上对标 [YogaDNS](https://inlhec.io/)：应用程序继续和 `8.8.8.8:53` 通信，
无需任何按应用配置，也永远不会知道真正应答的是别的解析器。

```
app ──sendto(8.8.8.8:53)──▶ WinDivert（拦截）
                              │
                              ├─ UDP ─▶ 192.168.0.1:1053
                              │           │
                              │◀── 应答 ──┘
                              │
app ◀──注入的应答（src=8.8.8.8:53）──┘
```

## 工作原理

1. **捕获。** 在 `Network` 层打开 WinDivert 句柄，过滤器为
   `outbound and (ip or ipv6) and udp.DstPort == 53 and not loopback`。
   环回流量对驱动不可见，因此被排除；过滤器同时排除我们自己上游 socket
   的源端口，避免抓到自己的查询。
   注意：WinDivert 2.2.2 拒绝编译 `not (udp.SrcPort == N)` 这种写法
   （即使已经有 `udp` 前置保护也不行），必须写成每个协议分支内使用
   `!=` 运算符的形式。
2. **解析。** IP/UDP 头和 DNS 查询在热路径上手工解析。`hickory-proto`
   只用于人类可读的 `--dump` 输出，绝不进入拦截路径。
3. **解析转发。** 查询载荷通过普通 UDP socket 发往上游，用一张以 DNS ID
   为键的 in-flight 表匹配应答。收到截断应答（TC=1）时自动改走 TCP 重试一次。
   上游 socket 必须先 `set_nonblocking(true)` 再交给 `from_std`——在
   Windows 上，阻塞模式的 socket 会让 worker 线程卡死在同步 `recv` 里，
   整个驱动从此不再消费命令。
4. **校验。** 应答的 ID 必须匹配且必须是一条响应。当应答携带 Question 区时，
   其 QNAME/QTYPE/QCLASS 必须与发出的提问一致，伪造或迟到的应答无法被注入。
5. **注入。** 构造完整的 IP + UDP + DNS 包，源地址填*原始*服务器，以
   **inbound** 方式注入，并从被捕获的查询包复制 `IfIdx`/`SubIfIdx`。驱动会
   重算校验和；impostor 标志清零时不递减 TTL，因此应用程序看到的应答与
   真实回包毫无区别。

### 防伪造（anti-spoofing）

设计上刻意校验上游应答而不是盲目信任：ID 会被改写为应用程序期望的值，
但应答中的 Question 必须与发出的提问对应。事务 ID、QR 位和 OPCODE 三者
全部校验；`QDCOUNT > 1` 的应答直接拒绝，`QDCOUNT == 0` 的应答仅凭 ID 接受。

### 测试

`testdata/` 内置假上游和端到端配置，见
[`testdata/README.md`](testdata/README.md)。`tests/e2e_pipeline.rs` 覆盖所有
不需要内核驱动的部分——真实 UDP 上游流量、防伪造拒绝、伪造包构造。
捕获与注入这两条系统调用只有提权后才会执行。

### 模式

| 模式 | 行为 |
| ---- | ---- |
| `hijack` | 拦截查询，交上游解析，注入伪造应答。默认。 |
| `forward` | 改写目的地址后交还内核投递应答（源 NAT）。要求上游为同地址族的 `udp://`；环回上游会被拒绝，因为驱动看不见环回流量。 |
| `passthrough` | 捕获的包原样重新注入。用于验证捕获路径。 |

### 失败行为

上游不应答时，由 `on_upstream_failure` 决定：

- `forward`（默认）——把原始查询交还给真实服务器，让应用退化为普通 DNS
  而不是干等到超时。
- `drop` —— 丢弃查询，让应用自己超时。

`forward` 模式有对应的安全网：如果上游应答在期限内没有回来，原始查询会被
重新注入到应用程序最初寻址的服务器。

## 环境要求

- Windows 10 或更高版本，x64。
- **管理员权限。** 打开 WinDivert 句柄需要提权。以服务方式安装时跳过检查，
  因为 SCM 已经以 LocalSystem 运行。
- MSVC 工具链（`x86_64-pc-windows-msvc`）。

## 构建

```sh
cargo build --release
```

产物是三个必须放在一起的文件：

```
target/release/dnsflt.exe
target/release/WinDivert.dll
target/release/WinDivert64.sys
```

`build.rs` 会把 `WinDivert.dll` 和内核驱动拷贝到可执行文件旁边，因为
Windows 加载器按运行中可执行文件的目录解析隐式链接的导入库。源码在
`vendor/windivert/`。

## 用法

```sh
dnsflt -c dnsflt.toml run          # 开始拦截（默认子命令）
dnsflt -c dnsflt.toml check        # 校验配置，显示生成的过滤器
dnsflt -c dnsflt.toml stats        # 查询运行中的实例
dnsflt install-service             # 注册为 Windows 服务
dnsflt uninstall-service
```

全局参数：`-c/--config <PATH>`、`-v/--verbose`（可重复）、`--log-level <LEVEL>`。

### 配置

完整带注释的示例见 [`dnsflt.toml`](dnsflt.toml)。未知键会被拒绝，拼错的
配置会立刻报错而不是被静默忽略。注意 TOML 语法：顶层键必须出现在任何
`[table]` 表头*之前*。

```toml
upstream = "192.168.0.1:1053"
mode = "hijack"
cache = true

[capture]
block_tcp_53 = false

[[rules]]
hostnames = ["*.ads.com"]
action = "block"
```

### 路由规则

规则按顺序求值，首个命中生效。模式匹配规则：

| 模式 | 行为 |
| ---- | ---- |
| `corp.local` | 命中 `corp.local` 及其所有子域 |
| `*.corp.local` | 仅命中子域，**不**命中裸域 `corp.local` |
| `*corp.local` | 命中任何以 `corp.local` 结尾的名字（含裸域） |
| `*` | 命中一切（catch-all，必须放最后） |

匹配不区分大小写。

```toml
[[rules]]
hostnames = ["ads.example.com", "*.tracker.net"]
action = "block"          # block | passthrough | server

[[rules]]
hostnames = ["*.corp.local"]
server = "10.0.0.53:53"   # 隐含 action = "server"
```

### 排除进程

我们自身的 PID 始终被排除，拦截器永远不会抓到自己的上游查询。要豁免第三方
进程，把它的 PID 列入 `capture.exclude_pids`。这需要预先知道 PID，对短命进程
不太现实；建议使用一组稳定的 PID，而不是依赖动态发现。

### 作为服务运行

```sh
dnsflt -c C:\dnsflt\dnsflt.toml install-service --start auto --start-now
dnsflt stats
```

服务默认以 LocalSystem 运行，注册的命令行里携带配置路径。`--start` 接受
`auto`、`demand`（默认）或 `disabled`；`--account` / `--password` 覆盖运行
账户；`--name` 和 `--display-name` 覆盖 SCM 标识；`--service-config` 固化一个
与安装时不同的配置路径。卸载用 `dnsflt uninstall-service --stop`。

## 统计

`dnsflt stats` 通过一个零依赖的 TCP 控制 socket（默认绑定回环
`127.0.0.1:53535`）与运行中的实例通信。该 socket 没有任何鉴权，必须保持在
回环地址上。常用参数：

| 参数 | 效果 |
| ---- | ---- |
| `--json` | 机器可读输出 |
| `--watch <MS>` | 每 N 毫秒刷新一次，直到被中断 |
| `--control <ADDR>` | 连接非默认端点 |

关键计数器：`captured`（捕获数）、`hijacked`（劫持应答数）、`injected`
（注入数）、`upstream_sent`/`upstream_recv`/`upstream_ok`（上游收发与成功数）、
`upstream_timeouts`（上游超时数）、`passed_through`（透传数）、`last_rtt_us`
（最近一次上游往返耗时，微秒）。`upstream_ok` 应随 `captured` 增长；
若只有 `captured` 增长而 `upstream_sent` 不动，说明上游驱动卡住——这正是
socket 阻塞模式问题的特征。

## 许可

`dnsflt` 以 [LGPL-3.0](LICENSE) 发布。对 `WinDivert.dll`（LGPL-3.0）是
**动态**链接，不静态链接也不内嵌驱动源码。`vendor/windivert/` 中的二进制是
未经修改的上游发行版，仅用于满足 DLL 与 `.sys` 运行时文件的需求；
`vendor/windivert/LICENSE` 含 LGPLv3、GPLv3 与 GPLv2 全文。分发
`dnsflt.exe` 即意味着同时附带这三个文件。