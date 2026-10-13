# VPSentinel 安全与可靠性整改记录

日期：2026-10-13。基线：`b7be8626a81b1ccb1bd39a9b5773becaa1417862`（v2.6.6）。

原始问题清单：[安全与技术评审](SECURITY-TECHNICAL-REVIEW-2026-10-13.md)。本文说明本轮代码整改、升级影响及验证边界。原始评审保留为历史记录，其行号和结论对应基线，不代表整改后的状态。

## 1. 安全问题整改

| 编号 | 本轮措施 | 相关实现 |
| --- | --- | --- |
| S01 | 动态文字转义；全部 19 处 HTML 写入经过本地 DOMPurify；动态操作改为固定动作表和数据属性，不拼接可执行事件代码 | `static/index.html`、`static/vendor`、`tests/frontend-security.cjs` |
| S02 | Mesh 强制验证证书与主机名，禁止明文连接；私有 CA 和内网目标需要显式配置 | `mesh_mgr.py`、`net_policy.py` |
| S03 | 管理 WebSocket 和管理状态接口拒绝订阅令牌；实时连接仅接收会话 Cookie；新增独立 Mesh 只读凭证；检查 Origin、连接数量、消息长度和超时 | `app.py`、`auth_mgr.py` |
| S04 | 配置、OCI 私钥和同步私钥从创建时即为 0600；同目录原子替换、fsync、拒绝覆盖符号链接；部署进程 umask 为 0077 | `secure_files.py`、`sentinel_core.py`、`cert_sync_mgr.py`、systemd 单元 |
| S05 | 初始明文密码不进入日志；安装器在启动前生成并通过终端交付；独立首次启动时使用邻近配置的 0600 临时交付文件，改密后删除 | `auth_mgr.py`、`scripts/install.sh` |
| S06 | Telegram 控制显式启用；群聊同时检查 sender ID 白名单；换 IP 不绕过额度；协程调度回主事件循环 | `bot_mgr.py` |
| S07 | 安全设置响应过滤会话密钥和密码哈希 | `auth_mgr.py` |
| S08 | 启用鉴权时缺失订阅令牌不再放行 | `auth_mgr.py` |
| S09 | 登录失败状态有 1024 桶容量上限；非法 IP 合并；清理过期项；增加全局一分钟预算并串行检查同一认证管理器的失败状态 | `auth_mgr.py` |
| S10 | 检查证书/私钥匹配、时间、指纹及指定 SAN；以完整版本目录和单一指针提交；重载失败回滚；自身重启只报告待确认 | `cert_sync_mgr.py` |
| S11 | 可配置外连使用统一 HTTPS 策略，禁止重定向和元数据目标；内网必须列入白名单；在连接时重新验证 DNS 并连接已核准的数值地址；响应限制 2 MiB | `net_policy.py`、Mesh/证书/通知/Bot 模块 |
| S12 | 本机 Hy2/Trojan 输出默认验证 TLS，订阅格式保持一致 | `sub_engine.py` |
| S13 | 更新直接依赖、锁定传递依赖和哈希；按 Python 3.10 解析完整锁文件；安装要求哈希校验；CI 执行漏洞扫描 | `requirements.in`、`requirements.txt`、CI |
| S14 | 取消远程安装回退；要求核对完整提交；第三方文件下载要求 HTTPS、固定版本和可信 SHA-256；停止执行未经核验的 3x-ui/acme.sh 网络安装器；CI Actions 锁定提交 | 安装脚本、`verified-download.sh`、README、CI |
| S15 | 关闭普通管理鉴权也不会公开证书私钥；私钥接口要求真实管理会话或专用同步令牌，并禁止缓存 | `app.py` |
| S16 | Web 服务采用普通用户、只读代码目录；根权限操作由检查 Unix peer credentials 的本地辅助服务处理；仅允许固定服务名/动作和固定路径节点配置；服务调用使用参数数组；校验中转脚本主机参数 | systemd、`privileged_helper.py`、`service_mgr.py`、`transit_mgr.py` |
| S17 | 会话校验用户名和未来时间；注销旋转密钥撤销现存会话；密码 12–1024 字符；PBKDF2 600000 次；成功登录升级旧哈希；首次密码必须修改；拒绝跨 Origin Cookie 写操作 | `auth_mgr.py`、`app.py` |

## 2. 技术问题整改

| 编号 | 本轮措施 |
| --- | --- |
| T01 | Hetzner Primary IP 默认拒绝本机执行；需要明确配置外部控制器；Floating 模式保留 |
| T02 | 提供商构造、旧 IP 查询等均进入修复例程的异常和 finally 保护；初始化失败不会遗留运行标记 |
| T03 | 配置变更采用可重入线程锁与跨进程文件锁；覆盖实际配置变更入口；Mesh 探测结果按 ID 合并，避免覆盖新增节点 |
| T04 | 持久化失败抛出错误；HTTP 系统/存储错误返回 503；不再保存失败后继续报告成功 |
| T05 | 阻塞路由进入工作线程；提供商构造、证书同步、通知和 DNS 重试从事件循环卸载；普通 settings 读取不再初始化 OCI 客户端 |
| T06 | Telegram 复用主循环；修复操作持久化阶段以阻止重复执行；管理任务集中记录，关闭时取消；后台采集器使用停止事件 |
| T07 | 持久化预检/换址/获得地址/完成/不确定阶段和操作 ID；额度在破坏性操作前预留；Lightsail 补偿未挂载资源并恢复旧绑定；Hetzner 检查 action 并补偿/开机；Azure 等待绑定确认才清理旧地址；OCI 删除错误不再吞掉 |
| T08 | 每轮独立处理 DNS 待同步地址；重试调用 DNS 驱动，不申请新 IP；更新成功清除待同步状态 |
| T09 | 全链路读取规范化 DNS 设置；支持 Cloudflare 和已确认返回地址的 HTTPS DNS 网关；未知驱动报错 |
| T10 | 更新已有 Cloudflare 记录时保留 proxied 和 TTL |
| T11 | 无服务管理后端时返回“不支持”；xray 不再映射为 x-ui；所有重载走服务后端；失败、待重启和完成分开表示 |
| T12 | 配置、静态资源、证书、OCI、流量和 3x-ui 路径集中解析；配置缓存指纹包含绝对路径；CLI 与服务读取同一运行时路径 |
| T13 | 引入 NodeSpec/ProxyDataSource，支持 SQLite 和配置节点来源；三种订阅复用有界缓存的本机节点快照；导出全部启用客户端；取消本机节点的固定 Oracle/US 名称。既有订阅规则渲染仍保留，后续可继续按中立模型拆分渲染器 |
| T14 | settings 未提交字段保持现值；掩码保持秘密，显式空字符串可清空；避免丢失 Telegram 控制设置 |
| T15 | 安装器先初始化认证、文件权限和辅助服务，再启动 Web 服务；不再与首次初始化抢先设置密码 |
| T16 | 测试始终使用新建的合成配置，覆盖继承的生产路径变量；隔离证书、OCI、流量和节点数据库；不复制生产凭据 |
| T17 | WebSocket 故障时每 15 秒轮询；重连采用指数退避与抖动；页面关闭清理定时器和连接 |
| T18 | 自动破坏性换址需要外部入站探针提供新鲜、目标 IP 一致的不可达证据；单纯出站丢包保持通知/人工复核；文案不再声称出站失败已证明入站封锁 |
| T19 | 增加提供商/模式枚举、端口/额度/密码等范围校验、HTTPS URL 和 UUID 校验；状态快照加锁并返回副本；存储失败统一响应 |
| T20 | 扩展后端安全、权限和补偿用例、前端注入/操作用例及 CI；Python 3.10 和 3.14 本地验证；真实云账户和新系统安装仍需要对应环境做验收 |
| T21 | Web 服务使用 StateDirectory/ReadWritePaths/专用用户；OCI 从 /root 迁移；代码只读；修正 Alias 段；单独辅助服务仅开放所需写入目录 |

## 3. 升级注意事项

### 3.1 安装与运行目录

从核对过的源码提交执行 `sudo bash scripts/install.sh`。远程拉取必须提供完整的 `VPSENTINEL_REF`，不会失败后回退到 main。

新部署布局：

- `/opt/vpsentinel`：root 所有的代码和虚拟环境，Web 用户无写权限。
- `/var/lib/vpsentinel`：服务用户数据、配置、流量库和 OCI 配置。
- `/etc/vpsentinel/cert`：服务用户可写证书目录，权限 0700；私钥 0600。
- `/run/vpsentinel-control/control.sock`：仅 root 和专用服务组可连接的固定操作入口。

安装器迁移现有配置及 OCI 文件。已有 3x-ui 数据库只授予读取 ACL，修改由辅助服务负责。没有 ACL 工具时安装器会明确报错，需要先安装相应发行版的 ACL 包。

不要单独替换旧 root 服务的 Python 文件：同时更新两个服务单元并执行安装器，才能获得新的权限边界。自定义部署需显式配置等效权限和路径。

### 3.2 凭证与首次密码

- 管理会话：Cookie/Bearer，仅用于管理；注销会撤销所有现存管理会话。
- `security.sub_token`：只用于订阅下载。
- `security.mesh_token`：只用于 `/api/mesh/telemetry`。Mesh 表单的监控凭证与订阅凭证分开填写。
- `cert_sync.sync_token`：专门访问证书同步接口；不通过 URL 参数传递。
- Telegram：设置 `notifications.telegram.bot_enabled=true`；群聊必须设置 `admin_user_ids`。

安装器通过终端交付初始密码。绕过安装器首次启动时，密码保存在配置旁的 `.initial-password` 文件中，改密后删除。日志不输出密码。首次设置或修改密码应使用至少 12 字符。

### 3.3 TLS、内网与自签名部署

`verify_ssl=false` 不再关闭身份验证。私有 CA 应配置 `network.ca_bundle`；内网目的地应加入 `network.allowed_private_hosts`，内容为精确主机名。链路本地/云元数据目的地即便列入白名单也会拒绝。

证书同步可设置 `cert_sync.expected_domains`；指纹、时间、私钥匹配检查始终启用。首次完成证书迁移后，稳定路径指向 `.current` 下的完整版本。自身服务重启返回 `reload_pending`，不能视为已经确认重启成功；重连后应核对服务和实际 TLS 证书。历史版本保留用于恢复，需按部署保留策略管理。

### 3.4 自动修复与恢复

`reip_auto` 还需要 `monitor.inbound_probe_url` 和可选 `inbound_probe_token`。外部 HTTPS 探针返回：

```json
{"inbound_reachable": false, "target_ip": "198.51.100.8", "timestamp": 1791849600}
```

`timestamp` 必须为当前 Unix 秒时间、误差小于 120 秒，地址必须与当前公网 IP 一致。未配置或验证失败时，只通知和人工复核。

`monitor.healing_operation.phase=uncertain/changing_ip/allocated` 会阻止盲目再次换址。管理员先在云控制台核对实例、地址绑定和遗留资源，再调用 `/api/heal/reconcile`：

```json
{"acknowledge_manual_verification": true}
```

该接口记录人工核对决定，不声称自动验证了云账户。DNS 待同步地址独立重试，不占用新的换址额度。Hetzner Primary 只有由另一台控制器管理目标服务器时才应启用 `hetzner.external_controller=true`。

### 3.5 新节点来源与 DNS

保留原 SQLite 来源，也可关闭它并使用配置节点：

```json
{"proxy_sources": [{"type":"config","nodes":[{"protocol":"trojan","type":"trojan","name":"Generic VPS","server":"node.example.com","port":443,"password":"replace-me","sni":"node.example.com","skip-cert-verify":false}]}]}
```

DNS 网关配置：`dns.type=webhook`、`dns.url`、`dns.record_name` 和 `dns.api_token`。网关接收 JSON `record_name/ip`，需返回 `success=true` 与相同的 `ip`；TLS、重定向和内网策略仍适用。Cloudflare 旧配置继续兼容。

### 3.6 下载完整性

3x-ui 和 acme.sh 需事先安装已核对版本。Realm、sing-box 和 Geo 文件下载需要固定 URL 与独立获取的 SHA-256；不提供哈希时不会执行或覆盖现有文件。校验下载内容不等于证明上游作者可信，必须从可信发布渠道核对版本和摘要。

## 4. 验证结果与边界

- Python 3.10.22：152 项测试全部通过，34.994 秒，无跳过项。
- Python 3.14.7：152 项测试全部通过，45.741 秒，无跳过项。
- 前端：19 处 HTML 写入检查、恶意名称/ID/动作属性和按钮点击用例通过。
- Python 致命语法/未定义名称检查、全部 Shell 语法检查、Git 空白检查通过。
- systemd 单元选项校验通过；校验时仅将不存在的安装解释器路径替换为本机解释器，不代表真实服务启动验收。
- 依赖从完整哈希锁文件安装，并进行了公开漏洞数据库检查；NPM 依赖审计无报告项。

验证覆盖合成配置、模拟云 API、前端 DOM 和锁定依赖，不连接用户云账户，不修改本机生产服务。

真实云资源替换、IAM、成本、外部路由、实际证书握手、发行版安装迁移和容器内权限必须在对应环境验收。特别是 OCI Ephemeral 地址释放后无法保证恢复原地址：失败恢复会尝试重新分配并保留不确定状态，必要时需要管理员从控制台处理。不能把单元测试通过理解为所有云故障可自动恢复，也不能把依赖扫描无已知漏洞理解为系统没有漏洞。
