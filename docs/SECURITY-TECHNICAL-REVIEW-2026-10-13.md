# VPSentinel 安全与技术审查报告

审查日期：2026-10-13（Asia/Shanghai）  
仓库：https://github.com/imprprpr/vpsentinel  
基线：`main` @ `b7be8626a81b1ccb1bd39a9b5773becaa1417862`，CHANGELOG 最新版本 v2.6.6。

## 1. 范围、方法和结论边界

本次重新检查了服务端路由、鉴权、会话、订阅渲染、云驱动、证书同步、Mesh、Telegram、安装脚本、路径和服务抽象、前端动态渲染，以及依赖与 CI。通过 GitHub API 确认提交编号，并下载该提交的固定源码快照；本地工作区仍停在较早版本，本报告行号全部指向上述远端提交，不能直接套用本地旧文件行号。

方式：静态代码审查、跨模块调用追踪、使用合成数据的隔离检查，以及维护者安全公告核对。隔离检查只使用内存配置和临时目录，未访问真实云账号、执行关机、修改真实配置、执行外部命令或攻击公网服务。没有运行完整测试套件、安装依赖，也没有进行真实 VPS 端到端部署。因此本报告不声称当前全部测试通过、所有云 API 均已实测，或已经找到所有潜在漏洞。

证据等级：

- **隔离确认**：在隔离环境执行相关原始函数/类，观察到了问题行为。
- **代码确认**：可以由明确的数据流、鉴权判断或执行顺序确认；未进行真实系统破坏性验证。
- **条件风险**：需要列出的部署方式、配置或攻击者权限才能触发。
- **改进建议**：未发现可直接成立的远程漏洞，但存在维护、可靠性或防护缺口。

本次整理 **17 项安全相关问题（S01–S17）** 和 **21 项技术改进（T01–T21）**。两类存在关联，不代表 38 个独立远程漏洞。P0 表示优先阻断可能导致接管、私钥泄漏或主机失联的路径；P1 表示下一轮应修复；P2 表示可安排在后续工程改造中。优先级并非 CVSS 评分。

已有改进值得保留：订阅令牌与证书同步令牌隔离、管理员 Cookie 的 Secure/HttpOnly/SameSite、可信代理链解析、配置原子替换、云探测 TTL 和互斥锁、路径集中化、服务/DNS 接口、测试沙箱、概览字段兼容。这些不等于相邻的攻击面也已经闭环。

## 2. 安全问题总览

| 编号 | 优先级 | 问题 | 主要触发条件 | 证据 |
| --- | --- | --- | --- | --- |
| S01 | P0 | 节点、Mesh 数据及日志进入 innerHTML，存在 XSS | 导入恶意节点或接入恶意/被篡改远端 | 代码确认 |
| S02 | P0 | Mesh 无条件关闭 TLS 校验，并允许 HTTP | 使用 Mesh；链路被拦截或误配 HTTP | 代码确认 |
| S03 | P1 | 订阅令牌可读取管理 WebSocket | 持有订阅 URL 的用户 | 代码确认 |
| S04 | P1 | 配置和私钥临时文件先以宽权限写入 | 常见 umask 022；本机其他账号可读目录 | 隔离确认/代码确认 |
| S05 | P1 | 自动生成的管理员密码进入日志 | 启动时没有密码哈希 | 代码确认 |
| S06 | P0（群聊配置） | Telegram 只校验群 ID，不校验发指令者 | 通知 chat_id 配成群/超级群 | 隔离确认 |
| S07 | P1 | 更新安全配置返回会话签名密钥和密码哈希 | 已登录管理员操作或 XSS 读取响应 | 隔离确认 |
| S08 | P1 | 缺失 sub_token 时订阅鉴权默认放行 | 配置被清空、损坏或手动删除令牌 | 隔离确认 |
| S09 | P1 | 登录限流容器无硬容量上限 | 大量不同地址/代理身份的活跃尝试 | 隔离确认 |
| S10 | P1 | 证书包缺少内容与密钥匹配校验，双文件更新不成事务 | 错误/恶意上游证书包或写入中断 | 代码确认 |
| S11 | P1 | 带凭据外连缺少协议、重定向和目标边界 | 管理员配置错误或不可信外连端点 | 条件风险 |
| S12 | P1 | 本地 Hy2/Trojan 订阅默认跳过证书验证 | 使用生成的 Clash/Sing-box 节点 | 代码确认 |
| S13 | P1 | 依赖锁在已有安全公告的旧版本 | 满足各公告适用条件 | 公告核对 |
| S14 | P1 | root 安装链下载可变上游且缺少完整性校验 | 上游、发布资产或下载链被替换 | 代码确认 |
| S15 | P1 | 关闭管理鉴权连带公开 TLS 私钥下载 | security.auth_enabled=false | 代码确认 |
| S16 | P2 | Web 控制面常驻 root，命令边界不够窄 | 管理面被接管；或未来接入不可信命令参数 | 代码确认/改进建议 |
| S17 | P1/P2 | 登出不撤销令牌，会话校验与密码策略仍可加固 | 令牌被复制；弱密码；签名密钥泄漏 | 隔离确认/代码确认 |

### S01：外部数据未经转义进入 HTML 和事件属性

位置：`static/index.html:2907`（中转）、`:2992`（独立节点）、`:3566`（日志）、`:5103`（Mesh）；`custom_node_mgr.py:25`、`:151`。

节点分享链接的 fragment 解码为 name，导入时保存，前端把 name/server/SNI 等插进 `innerHTML`；Mesh 的远端 pub_ip/uptime 等也直接插入模板。日志的 msg/level/time 同样未作 HTML 转义。Mesh 删除按钮还把 name 插进单引号包围的内联 onclick，存在 JavaScript 属性上下文风险。

这不只限于管理员自行填写恶意文本：用户会导入第三方分享链接，远端 Mesh 会返回未经信任的状态；S02 又允许链路篡改。攻击者控制这些输入后，可在管理员浏览页面时以该站点身份发 API 请求。HttpOnly 能阻止直接读取 Cookie，但不能阻止页面脚本携带 Cookie 操作管理 API。

建议：文本字段使用 textContent；用 createElement 构建 DOM；按钮使用 addEventListener 和内部 ID，不拼接内联事件。需要 HTML 的内容使用经过维护的 sanitizer，分别处理 HTML/URL/属性上下文。CSP 是辅助防护，当前大量 inline script/onclick 需要先迁移。

验收：导入包含 HTML 标记、引号及事件属性的节点名称；模拟远端状态字段和日志含这些文本；所有页面显示纯文本且无脚本执行。不要只检查数据库中是否存在字符。

### S02：Mesh 默认不验证远端身份

位置：`mesh_mgr.py:109–116`、`:154–160`、`:235–241`。

远端状态探测和订阅拉取均设置 `check_hostname=False`、`CERT_NONE`；host 还允许 http://。状态请求发送 Bearer 凭据，订阅请求把 token 放在 URL。链路被拦截时可能泄漏凭据、伪造主机状态、替换代理服务器/凭据，并放大 S01 的影响。并非只有可用性探测受到影响。

建议：默认 HTTPS 且校验证书。自签部署使用可配置 CA 或首次经管理员确认的证书/公钥 pin，不长期关闭校验。管理状态与订阅拉取使用不同 scope 的令牌。订阅令牌优先通过 Authorization 发送。

验收：不受信证书连接失败；配置正确 CA/pin 后成功；HTTP 端点被拒绝或要求明确的高风险确认。

### S03：订阅令牌越过监控权限边界

位置：`app.py:1551–1588`；`static/index.html:3526–3532`。

WebSocket 接受管理员会话或 sub_token。连接后发送主机指标、IP、探针、运行日志、测速及自动修复状态，而这些内容对应的 REST 管理接口多数要求管理员。前端还主动把 sub_token 拼到 WebSocket URL。订阅链接转给别人，实际上也分享了管理遥测访问权。

建议：管理 WebSocket 只允许管理员会话或专门的只读监控令牌；sub_token 只下载订阅。增加 Origin 校验、连接数量/消息大小/空闲超时限制。不能把 HTTP 中间件当成 WebSocket 已具备的 Host/IP 防护。

验收：仅持订阅令牌连接被拒绝；管理员连接成功；错误 Origin 被拒绝；超量连接被限流。是否提供公开遥测应由独立配置明确决定。

### S04：敏感文件权限是在写完之后才收紧

位置：`sentinel_core.py:338–345`；`cert_sync_mgr.py:338–345`；`sentinel_core.py:1504–1506`；`scripts/wizard.py:486–488`。

`open(..., 'w')` 使用进程 umask 创建文件，配置写完并 replace 后才 chmod 0600；证书私钥临时文件也是先写再 chmod。隔离检查在 umask 022 下观察到配置临时文件为 0644，最终文件为 0600。因此“最终权限正确”不等于写入全过程保密。

建议：在创建时使用 0600（os.open 配 O_CREAT/O_EXCL，或安全临时文件 API），目录收紧到 0700；拒绝符号链接覆盖；写入后 fsync，再原子替换，清理失败临时文件。密钥写入失败或权限设置失败不能静默忽略。

验收：在写入中途检查文件模式；注入异常后不遗留可读秘密文件；并发写入不共用临时名称。

### S05：初始密码写入持久日志

位置：`auth_mgr.py:57–66`；`scripts/install.sh:135–175`。

AuthManager 在启动时生成口令，并用 logger.warning 打印完整密码。systemd 会将其记录到 journal。此前“磁盘不存 initial_password”的整改没有消除日志中的明文副本。安装器又先启动服务后生成密码，存在 T15 的竞争。

建议：安装阶段先生成并持久化哈希，只将一次性口令交付给当前终端；服务启动不能打印凭据。密码未初始化时采用显式的一次性 setup secret 或安全的本机恢复流程。

验收：干净安装时终端能获得有效口令；journal 和日志文件中没有该口令；导入模块不自动生成或打印凭据。

### S06：配置 Telegram 群通知等于授权全群操作

位置：`bot_mgr.py:275–345`、`:185–230`、`:32–36`。

文本和 callback 只比较 chat.id 与 admin_chat_id，未校验 `message.from.id` / `callback_query.from.id`。当 chat_id 是群 ID 时，群中其他成员发送命令或点击按钮也会通过；换 IP 使用 force=True，可绕过冷却和配额。隔离检查使用非管理员 from.id、已配置群 ID 的 callback，确认到达换 IP 处理器。

此外，凭据存在时 `bot_enabled` 的 OR 判断会启动 Bot，即使通知总开关关闭；通知配置与远程控制授权因此混在一起。

建议：通知 chat_id 与控制用户 allowlist 分开；默认只允许指定用户的私聊控制；群模式同时校验群、发送者和控制开关。高风险操作确认需绑定用户、操作与有效期，不能只信任固定 callback_data。force 权限单独控制。

验收：群内普通成员和匿名发送者不能换 IP/拿订阅；授权用户可以；关闭 control_enabled 后任何指令都不执行。

### S07：安全设置响应泄漏内部签名材料

位置：`auth_mgr.py:343–352`；`app.py:700–704`。

update_security_settings 返回整个 security 段，API 原样发回，包含 session_secret、admin_password_hash、sub_token。隔离确认响应对象包含前两项。这里有管理员鉴权，不应描述为未经授权直接泄漏；但它把服务端密钥复制到了浏览器、调试记录和前端脚本可读范围。

建议：使用响应白名单。哈希和 session_secret 永不返回；新订阅令牌仅在明确轮换操作时交付。包含秘密的响应设 Cache-Control: no-store。

验收：每个安全设置操作的响应均不存在签名密钥/密码哈希，包含显式 null 值的更新也应拒绝或规范化。

### S08：订阅令牌缺失时 fail-open

位置：`auth_mgr.py:247–261`。

auth_enabled=true、管理员未登录时，若 expected_sub_token 为空，verify_subscription_access 返回 True。隔离确认空令牌且没有任何请求凭据也通过。受影响的不止订阅，还包括使用同一 helper 的 IP 体检和 Host Guard 分支。

建议：没有令牌就拒绝访问并记录配置错误，或安全生成并保存令牌；不能把“尚未配好”解释为“公开访问”。相关配置加载失败也应保持封闭。

验收：令牌缺失/空/null/配置损坏时匿名请求全部拒绝；管理员恢复入口仍可用。

### S09：登录限流只清理过期项，没有容量上限

位置：`auth_mgr.py:122–152`；`app.py:130–164`。

超过 1000 桶后只删除过期条目，活跃条目仍可无限增加。隔离检查连续插入 1500 个新身份，容器保持 1500。该检查证明容量缺口，不能据此声称所有部署都能伪造来源 IP：正常直连/正确追加真实来源的反代不允许任意换键。大量真实来源、错误信任的代理头或不验证的非 IP 头值会扩大风险。

建议：固定容量、TTL/LRU、全局预算及按账号限流；IP 值严格解析；超限响应使用 429；PBKDF2 工作放入受限执行器。单进程内存限流不足以覆盖多 worker，应限制部署模式或使用共享存储。

验收：大量活跃身份不突破容量；并发失败计数稳定；不同 worker 无法轮流绕过限制。

### S10：证书和私钥包未经充分验证就覆盖本地文件

位置：`cert_sync_mgr.py:318–359`、`:558–575`。

收到非空 cert_pem/key_pem 即写盘，没有先确认 PEM 可解析、密钥与证书匹配、SAN/有效期符合目标，也未自行计算并比较探测和下载的 fingerprint。fingerprint 来自同一远端，不能替代身份认证。私钥先替换、证书后替换，第二步失败会留下不匹配文件；成功后又未以 reload 结果决定同步成功。

建议：先验证链、SAN、有效期和公钥匹配，在临时版本目录中完整准备，再通过目录/符号链接切换一次提交；保留前一版本并可回滚。计算实际 fingerprint，处理探测与下载间证书更新的竞争。私钥下载响应禁止缓存，限制响应大小。

验收：不匹配、损坏、过期或目标域名不符的包不覆盖旧证书；模拟中途写入/重载失败能恢复；明确报告 partial/failed。

### S11：外连目标、HTTP 和重定向策略不明确

位置：`mesh_mgr.py:94–116`、`:224–241`；`cert_sync_mgr.py:263–309`；通知 custom webhook 路径。

Mesh 支持 HTTP，证书 master_url 也没有强制 HTTPS；关闭 verify_ssl 时没有身份 pin。凭据请求使用 urlopen 默认重定向机制，未限制目的主机；也未限制响应大小。管理员能配置任意地址，因此不能把 SSRF 描述为匿名直接可利用；风险在于配置误导、被攻陷端点重定向，或其他漏洞取得管理写入权后的横向探测与凭据转发。

建议：含凭据请求必须 HTTPS；禁止跨主机重定向或每跳重新校验且不转发 Authorization；按功能区分公网外连与明确授权的私网 Mesh，不能简单禁止一切私网地址。阻止未授权的 link-local 元数据目标，限制 DNS 重绑定、响应大小、并发和总超时。

验收：跨域重定向不携带令牌；未授权元数据地址不可访问；显式授权私网节点可正常工作。

### S12：生成的节点默认跳过 TLS 验证且不同格式不一致

位置：`sub_engine.py:164`、`:180`、`:719`、`:751`。

从数据库提取的 Hy2/Trojan 设置 skip-cert-verify=True，Clash 等消费该值；Hy2 分享链接却生成 insecure=0。结果既存在中间人防护缺口，也造成“一个客户端可连、另一个证书报错”的体验差异。

建议：默认启用校验，证书/SNI/信任方式进入中立 NodeSpec；确需自签的节点明确选择 CA/pin 或显式 insecure，所有渲染器遵循同一策略。

验收：同一节点在各格式中 TLS 安全语义相同；错误证书不能默默通过。

### S13：依赖存在已知安全维护欠账

位置：`requirements.txt:1–11`。

requests 被固定到 2.31.0。维护者公告 GHSA-9hjg-9r4m-mvj7 / CVE-2024-47081 指出 <2.32.4 的版本在特制 URL 和 .netrc 条件下可能泄漏凭据。该版本确属受影响范围，但本项目是否可达该利用路径还取决于真实 .netrc、URL 来源和请求流程，不能直接称为已利用。

FastAPI 0.110.0 对应的旧 Starlette 兼容范围也需要更新。GHSA-f96h-pmfr-66vw 的 multipart DoS 要求应用接受表单请求；当前主要路由为 JSON，且 requirements 未显式安装 python-multipart，因此该公告是依赖升级依据，不是本次确认的可达匿名漏洞。cryptography 使用宽下限，传递依赖也没有完整 lock/hashes。

建议：在兼容环境解析实际依赖树，使用 pip-audit/OSV 扫描并区分 affected 与 reachable；整体更新 FastAPI/Starlette/HTTP 客户端；建立带哈希的部署锁文件与周期更新机制。不要仅把所有库固定在很旧版本。

公告：

- https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7
- https://github.com/Kludex/starlette/security/advisories/GHSA-f96h-pmfr-66vw

### S14：安装供应链缺少可追溯与完整性保护

位置：`scripts/install.sh:17`、`:59`；`scripts/node_provisioner.py:97`；`scripts/setup-relay.sh:69–72`；`transit_mgr.py:65–82`；`scripts/update-geo.sh:17–23`。

默认跟随 main，某个 ref clone 失败后回退默认 clone；3x-ui 直接下载 master 脚本管道执行；Realm/规则资产来自 latest，缺少摘要或签名校验。脚本和二进制以 root 执行，HTTPS 仅验证传输端点，不能固定上游内容。

建议：发布包默认固定 commit/tag；显式 ref 失败应报错；下载到临时位置，核验签名/预先公布的摘要，再安装。记录版本与摘要，提供回滚。Geo 数据更新也应先下载验证再替换，不能直接覆盖正在使用的文件。

验收：摘要不符、版本不存在、下载不完整时停止；旧版本继续可用；安装记录可以还原来源。

### S15：关闭管理鉴权会公开私钥接口

位置：`auth_mgr.py:232–236`；`app.py:1692–1721`、`:1765–1780`。

auth_enabled=false 时 is_request_authenticated 对任何请求返回 True；verify_cert_key_access 首先使用该 helper，导致 /api/cert/bundle 不再需要管理员或 sync_token。这里是配置触发，不是默认配置的漏洞；但“关闭控制台密码”意外同时撤掉私钥下载保护，边界过宽。

建议：TLS 私钥 API 始终需要独立鉴权，即使普通面板处于免登录模式；或关闭鉴权时直接禁用私钥远程导出。对外暴露该模式应明确提示。

验收：免登录面板下匿名请求仍无法下载私钥，独立 sync_token 仍可用。

### S16：root 控制面和 shell 接口扩大失陷后果

位置：`systemd/vpsentinel.service:8–19`；`service_mgr.py:35–57`；`sentinel_core.py:1228`；`transit_mgr.py:67`。

服务常驻 root，持有云/DNS/证书凭据。自定义 hook 执行任意 shell 是管理员授权能力，不应误报成匿名 RCE。新增 ServiceManager 用 shell=True 拼服务名；当前证书调用路径主要传固定允许名称，本次未确认普通用户可直接注入，但接口复用后易产生漏洞。生成 relay 脚本也将配置域名直接插入 shell 字符串。

建议：Web 进程使用专用用户；需要 root 的重载/防火墙操作通过小型 helper 和固定 allowlist 完成。subprocess 使用参数数组、超时和输出上限；服务名和域名做语义校验；hook 作为独立高级权限功能，记录审计。为真实需要的目录配置写权限，勿盲目增加沙箱指令导致服务无法运行。

验收：普通 Web 进程不能修改任意系统文件；服务名含 shell 元字符被拒绝；hook 超时能够结束且不占住修复状态。

### S17：会话撤销、身份检查与密码策略

位置：`app.py:670–673`；`auth_mgr.py:194–229`、`:330–341`；`app.py:642–653`。

登出仅删除当前浏览器 Cookie，复制出去的 Bearer 会话仍有效直至最长 30 天；必须改密/轮换 secret 才全局失效。校验不检查 token 的 username 是否为当前管理员，也只检查过期、不拒绝未来时间戳。隔离确认：使用合成签名密钥签出的“其他用户 + 未来时间”令牌被接受；这需要能签名，不能单独作为伪造会话漏洞，但与 S07 构成危险组合。

密码仅要求 6 字符，PBKDF2 100000 次没有可升级的成本策略；must_change_password 主要是响应提示，未作为敏感操作前置限制。强制改密策略如要成立，应由后端执行。

建议：增加 session ID/version 与撤销能力；按当前用户/允许时钟偏差验证；缩短默认会话并提供“登出所有设备”。密码长度和弱密码拒绝策略统一；按服务器能力评估哈希成本，支持成功登录后升级。升级认证库时保留兼容迁移。

验收：登出后旧令牌失效；改用户名后旧身份失效；未来时间戳拒绝；未完成首次改密不能调用高风险管理接口。

## 3. 技术问题与改进路线

| 编号 | 优先级 | 问题 | 位置 |
| --- | --- | --- | --- |
| T01 | P0 | Hetzner 本机 Primary IP 换址流程会关闭自己 | sentinel_core.py:1006–1045 |
| T02 | P1 | healing 标记在 try/finally 之前置位，异常会卡死 | app.py:1385–1400 |
| T03 | P1 | RLock/update 接口存在，但多数写入仍是分离读改写 | app.py:484；mesh_mgr.py:40；auth_mgr.py:330 |
| T04 | P1 | 配置保存失败仍报告成功 | app.py:601、:953、:1019；auth_mgr.py:330 |
| T05 | P1 | 多个 async 路由和监控逻辑仍同步执行 I/O | app.py:420、:732、:1670、:1790 |
| T06 | P1 | Bot 跨线程创建新事件循环，修复任务缺少统一入口 | bot_mgr.py:185–230；app.py:1510 |
| T07 | P1 | 云换 IP 未形成可恢复事务、资源清理不完整 | sentinel_core.py:704–765、:850–890、:952–1058、:1138–1207 |
| T08 | P1 | DNS 失败只留 pending 标志，缺少重试协调器 | app.py:1424–1459 |
| T09 | P1 | DNS 抽象调用仍被旧 cloudflare 配置硬门控 | app.py:1392–1447；sentinel_core.py:1454–1470 |
| T10 | P1 | DNS 更新强制关闭 Cloudflare Proxy | sentinel_core.py:1416、:1433 |
| T11 | P1 | Noop 服务管理把未执行当成功；服务映射不准确 | service_mgr.py:64–77；cert_sync_mgr.py:380–419 |
| T12 | P2 | paths 集中化未覆盖全部路径与环境变化 | paths.py:31–40；sentinel_core.py:287–294 |
| T13 | P2 | 数据源与渲染仍耦合，三种订阅重复聚合 | sub_engine.py:83、:310、:696、:796 |
| T14 | P1 | settings 部分更新会重置通知配置 | app.py:378–399、:560–598 |
| T15 | P1 | 安装器先启动服务再生成密码，首次交付有竞争 | scripts/install.sh:135–175 |
| T16 | P1 | 测试沙箱在已有 CONFIG_PATH 环境变量时失效 | tests/sandbox.py:16–24 |
| T17 | P2 | WebSocket 断线 fallback 只是单次 fetch | static/index.html:3548–3557、:3658–3669 |
| T18 | P1 | 出站探测不是国内入站可达性证据 | sentinel_core.py:458–509；app.py:327–350 |
| T19 | P2 | 配置模型及响应契约校验不完整 | app.py:SettingsModel/CertConfigModel/SetupSaveModel |
| T20 | P2 | 缺少完整安装、真实客户端与失败恢复验证 | .github/workflows/lint-and-test.yml；tests/ |
| T21 | P1 | systemd 只读保护与默认证书/OCI 写入路径冲突 | systemd/vpsentinel.service:17–18；sentinel_core.py:144 |

### T01：不能由目标服务器自行完成需要关机的换址

Hetzner Primary IP 流程先 poweroff、等待 off，随后 unassign/assign，再 poweron。如果 VPSentinel 就运行在该目标机，关机时执行进程停止，后半段不会发生；systemd Restart 无法让已经关机的 VM 自动开机。此结论针对同机部署，外部控制节点则不受“关闭自己”这一条件影响。

方案：将该驱动限定为外部控制平面执行；本机模式明确拒绝并解释原因；任务状态存放在控制节点，并保证 poweron 的补偿流程。浮动 IP 方案还需操作系统配置与回程验证，不能只因 API 返回新 IP 就认为能接入。

验收：同机部署请求在 poweroff 前被拒绝；外部控制模式在中途 API 失败时能恢复旧绑定和开机状态。

### T02：修复标记可能永久保持 True

置位后调用 monitor.get_public_ip、广播、sleep 和 get_cloud_provider，随后才进入 try。构造器或这些前置步骤异常时不会走 finally。隔离检查令 provider 构造抛错后，heal_in_progress 仍为 True，所有后续触发均被拒绝。

方案：锁定后所有逻辑立即放入 try/finally，保存和恢复状态；显式处理取消；避免为了报告错误又让通知异常盖住原始错误。验收覆盖构造、预检、换址、DNS、通知、取消各阶段失败。

### T03：配置事务化尚未覆盖实际调用者

load 和 save 各自加锁不能保护中间的修改。Mesh、自定义节点、中转、安全更新、settings 和证书状态各自持有不同锁或无锁，两个调用可能从同一旧配置覆盖彼此更新。已有 ConfigManager.update 应成为所有写路径的共同入口。初始化、轮换令牌、改密也需事务化；多进程场景还需文件锁或数据库事务。

验收：并发改节点、改密码和保存设置后所有修改保留；不能仅测试两个 save 都返回 True。

### T04：保存失败应传播给调用者

多个接口忽略 save 的布尔返回值；auth.update_password 甚至无论落盘是否成功都返回 True。用户会看到成功，重启后配置又恢复；重登录可能使用旧密码。方案：持久化失败抛结构化错误，接口返回失败码；状态切换/任务启动发生在成功提交之后。覆盖只读目录、磁盘满、replace 失败。

### T05：事件循环卸载只完成了一部分

get_settings 每次创建 OracleManager，含同步 metadata/SDK 初始化；setup/status 同步云探测和公网 IP 查询；Mesh refresh、证书同步、通知发送仍在 async 流程直接执行同步网络/进程操作。重载和 hook 还可能长期等待。

方案：所有阻塞 I/O 移入受限执行器/任务队列或 async HTTP 客户端；设置总时限、取消和背压；缓存 provider ready 状态；非 OCI 模式不初始化 OCI。单纯无限放进默认线程池会把阻塞转为线程耗尽。

### T06：统一修复任务调度与互斥

Bot 的工作线程没有主事件循环时使用 asyncio.run，修复流程便在第二个 loop 上执行，却仍访问共享 runtime_state 和主 loop 的 WebSocket。布尔标记也不是跨线程互斥锁；任务没有持久 task ID、进度查询和可靠取消。

方案：启动时保存主 loop 引用，Bot 用 run_coroutine_threadsafe 提交到该 loop；HTTP/Bot/自动监控统一任务服务；用真正的锁/租约保证单任务。多 worker 需共享任务状态。验收同时从三个入口触发时只执行一次，且 WebSocket 更新正常。

### T07：换 IP 驱动需要计划、执行、验证、补偿四阶段

Oracle 的先释放旧 IP 再分配加一次紧急重试不是完整回滚；Lightsail Attach 失败缺少新资源清理；Hetzner 部分非成功 HTTP 状态没有立即失败，浮动模式未形成旧资源替换与系统网络配置流程；Azure 选择 ipConfigurations[0]，未按 primary 选择，且缺少 NIC 长操作完成和实际绑定的完整验证。

方案：每个驱动返回 OperationPlan/Result，显式标记会中断网络/需要关机/能否回滚；先检查配额与实际修改权限；保存旧绑定和操作 ID；轮询动作；验证目标实例入口而不只检测本机出口；成功后再清理旧资源。失败后记录新资源 ID，交给补偿/人工恢复，不无限重试换址。不要为了测试真实释放生产 IP。

### T08：DNS 失败后需要重试 DNS，不应再次换 IP

dns_sync_pending 被写入配置，但未发现消费该标志的协调器。失败后可能留下新 IP、旧 DNS，配额/冷却又阻止继续修复。方案：持久化 DNS-only 任务，指数退避、最大时限、明确告警；观察当前实际 IP 后重试；重启继续任务。DNS 成功最好查询权威记录验证，不只相信 HTTP JSON success。

### T09：DNS 解耦仅完成接口外壳

run_healing_routine 仍从 cloudflare 段取 token/zone/record，并以旧 token/record 决定是否调用 get_dns_provider、DNS 是否必需。仅填 dns 段可创建 provider，却仍被修复流程跳过。未知 dns.type 会降级成 Cloudflare，有误投配置/凭据的风险。

方案：统一解析为 DnsConfig（type、zone、record、credentials、enabled），旧字段只在配置迁移层映射；流程只依赖接口。未知类型必须报错；至少完成第二个 provider 才能证明抽象有效。设置/向导/Bot/Host Guard/订阅域名也要同时迁移。

### T10：换 IP 不应悄悄关闭 CDN 代理

更新 A 记录时写死 proxied=False，会把已有橙云记录变成灰云，改变访问路线并暴露源站。方案：读取保留原 record 的 proxied/TTL 等策略，或将该行为设成独立显式配置；新建记录和更新记录分别处理。验收橙云记录换 IP 后仍是橙云，不能仅断言 content 正确。

### T11：服务抽象需表达“不支持”，不能伪造成功

Noop.reload/restart/is_active 均返回 True；容器里证书落盘不代表进程已重新加载。证书同步又不检查全部 reload_results。别名 xray/3x-ui 一律 reload x-ui；oracle-sentinel 重启被映射成 vpsentinel，旧版服务可能无法重启；nginx/caddy 仍直接执行命令。

方案：返回 supported/executed/success 三种状态；按真实服务名/后端映射；使用 signal/hook/container API 实现真正重载；汇总 partial/failed，验证证书实际生效后再报成功。

### T12：路径解析需要一个运行时契约

CONFIG 支持环境覆盖，STATIC/TRAFFIC 仍按 /opt 存在性选路径，HOME 不一致影响全部数据；CERT_DIR 默认 BASE_DIR/cert，与 systemd 的 /etc/vpsentinel/cert 不一致。部分常量在导入时固定；get_active_config_path 会优先取模块常量，HOME 在进程中改变后未必生效。缓存 fingerprint 也未包含配置路径。

方案：创建不可变 RuntimePaths，在启动时一次解析并校验；各模块通过注入引用；配置缓存键包含 path；覆盖 config/static/traffic/cert/db/node_provisioner 全路径。明确环境变量仅启动生效还是支持热更新。

### T13：使用中立节点模型统一数据源与渲染

DB 路径和 schema 固定 3x-ui；只取首个 client；节点地域/名称固定 Oracle/US；三个输出分别聚合中转、自定义、Mesh/EDT；Base64 名称与其他格式不一致。不能将 NodeSource 改造简化成移动文件或改 DB_PATH。

方案：NodeSpec 包含 protocol、endpoint、auth、transport、TLS、source_id/client_id；XuiDbSource/ManualSource/EdgeSource/MeshSource 输出统一模型；一次采集后交给独立渲染器。明确哪些协议和 transport 支持，拒绝静默丢弃；输出用真实核心解析器验证。核心版和完整版复用同一装配树。

### T14：settings 更新应保留未提交字段

通知字段默认 False/空，接口无条件重建通知对象。仅提交 cf_record 或 provider_type 可能关闭所有通知、清空 chat_id。部分 secret 用 **** 字符判断保持旧值，也使清空/实际更新语义模糊。

方案：使用 exclude_unset 和事务 patch，仅更新显式字段；secret 用 omitted/update/clear 明确语义；禁止 null 非法字段；GET/POST 模型分别定义。setup/save 覆盖 notifications 也应与脱敏回填保持一致。

### T15：安装密码生成存在真实执行顺序竞争

installer 先 restart 服务，再查询公网 IP，再运行密码初始化。app 导入 AuthManager 后也会生成密码：服务先到达则终端得到 [EXISTING] 而不知道初始口令；并发读改写还可能覆盖不同密码。以前只隔离测试密码生成代码片段不足以证明安装链通畅，本次据完整顺序修正此前“完全闭环”的评价。

方案：先初始化凭据及配置，再启动服务；启动初始化和安装初始化不得各生成一份；初始化要可重入并防并发。验收在全新环境完整执行安装器，终端打印的口令能登录，日志无明文，重复安装保留原密码。

### T16：沙箱不能因为已有环境变量而跳过

tests/sandbox.py 只有在 VPSENTINEL_CONFIG_PATH 不存在时才创建临时配置。如果操作者从生产 service 环境运行测试，该变量本来就指真实文件，测试会直接修改它。复制真实配置到沙箱还把真实凭据带进测试；沙箱只覆盖 config，不自动覆盖 traffic、cert、OCI 和外部网络/服务命令。

方案：总是覆盖到新的临时目录，结束恢复环境；从合成安全 fixture 初始化；集中覆盖所有写路径与有副作用的接口；禁止默认外网。单文件执行、discover、已存在 env 三条路径都应验证。不能因为新增一项 mtime 测试就称“全量零宿主写入”。

### T17：断线后需要真正的周期轮询和停机条件

onclose 调一次 loadOverviewStatus，然后 3 秒后重连；并没有在 WebSocket 不可用期间启动轮询 timer。重连每次关闭能偶然产生 fetch，但不是可靠 fallback，且无退避，多个 tab 会放大连接压力。方案：单一连接状态机，带抖动指数退避；断线启动单个轮询，恢复时停止；注销清理所有 timer/连接；401/403 不继续重试。

### T18：区分出站探测与入站失联

国内探针代码从 VPS 发 TCP connect，返回 direction=outbound。它能证明 VPS 到指定目标端口的连接质量，不能直接证明国内客户端到该 VPS 的入站端口被阻断，也不代表代理协议健康。低于 75% 的自定义 loss_threshold 与 uplink_alive 的固定 75% 检查还有不一致。

方案：把状态命名为 outbound_degraded；加入用户侧/第三方入站探针或多地可信 agent；分别报告主机上行、目标可达、入口可达、协议健康。自动换 IP 需要足够证据和可配置策略，而非把普通目标故障定性为封锁。防止失败风暴引发频繁通知。

### T19：统一输入校验与状态/响应模型

cert role、provider type、自动修复模式使用任意字符串；poll interval 可填不合理值；部分字段是 Optional 但下游 strip/int 假定有效；UUID 验证失败又回退原文本；IP 常以字符串拆分判断。状态缓存返回共享 dict，指标采样和并发刷新缺少一致性保证。

方案：枚举、范围、IP/URL/UUID 语义校验、响应 DTO；配置 schema_version 与迁移；快照锁/单次刷新；模型不混合秘密与 UI 字段。兼容字段写清弃用周期，避免长期 public_ip/current_ip 两套契约。

### T20：将验证从“函数通过”扩展到完整用户路径

CI 目前以语法/未定义名称检查和单元测试为主；矩阵只有 Python 3.10–3.12。CHANGELOG 的测试数量和耗时是发布说明，本次未重新运行，不能当成本次实测证据。当前依赖较旧，新发行版默认 Python 与依赖 wheels 也可能不兼容。

方案：保持离线单测，增加安全权限矩阵、真实文件故障注入、浏览器 XSS/登录/向导、全新 VM 安装升级、真实 Xray/Clash/Sing-box 配置解析，以及可选的独立沙箱云账户集成测试。计时不要作为机器无关的硬指标；禁止测试使用生产凭据。README 明确验证过的发行版/Python/部署形态。

### T21：默认服务沙箱阻止自身需要的写入

服务单元设置 ProtectSystem=full、ProtectHome=read-only，没有为默认 `/etc/vpsentinel/cert` 或 `/root/.oci` 配置可写例外。在支持这些 systemd 保护的默认部署中，Web 生成 OCI 密钥/配置、edge 证书写入因此与只读挂载冲突。安装器在服务之外生成自签证书成功不能证明服务进程随后可以更新证书；直接运行 Python 的测试也不会复现这个挂载限制。该结论来自单元与路径对照，未在真实 systemd VM 中重演。

方案：把可变状态移至受控状态目录，私钥保留最小读写权限；确需写默认目录时为专用目录设置精确 ReadWritePaths，并保证目录由安装器预创建。不要整体关闭 ProtectSystem/ProtectHome。Web 本身继续采用 S16 的降权与 helper 方案。另将 Alias 放在 systemd 支持的 [Install] 段，安装流程明确验证兼容别名。

验收：在原样 service 单元下完成 Web 密钥初始化、edge 同步及重载；普通接口仍不能写 `/etc`、`/root` 的其他路径；journal 无 Read-only file system 错误。

## 4. 修复与精简的建议顺序

1. **先补安全边界**：S01/S02/S06、S03/S07/S08/S15，T01/T02/T15。先消除外部数据接管页面、错误授权和主机失联。
2. **再补持久化和恢复**：S04/S05/S10，T03/T04/T06/T07/T08/T10/T21。每个失败状态必须能恢复并得到正确反馈。
3. **建立安全运行基线**：S09/S11/S13/S14/S16/S17，T05/T11/T16/T20。依赖升级、受限执行器、凭据保护和隔离验证作为持续流程。
4. **再收敛核心代码**：T09/T12/T13/T14/T17/T18/T19。节点模型和模块边界建立后，以同一源码的 core/full 装配发布；HTTP 路由、后台任务、依赖和前端菜单都按模块启用。

精简版最小闭环建议为：鉴权/配置 → 状态与可信探针 → 换 IP 任务 → DNS 同步/补偿 → 通知 → 单一节点模型与订阅。Telegram 控制可选，证书“本机使用”和“跨机私钥分发”分开。Mesh、全带宽测速、IP 画像、流量账单、Realm 脚本和微服务入口可放可选模块。不能因模块叫外围就直接删除；也不能把无操作返回成功当精简完成。

把 APIRouter 抽取称作“纯剪切粘贴、零风险”不准确：它同时涉及全局鉴权对象、配置注入、启动任务、WebSocket、模型和前端调用。先定义组件接口和权限清单，再小步抽取；路由快照要包含 method、path 和依赖权限，单看 path 不足以证明等价。

## 5. 本次隔离检查记录

用最新快照中的 AuthManager、ConfigManager、run_healing_routine 和 TelegramInteractiveBot 的原始定义执行；配置为合成内存对象，文件仅在 tempfile 目录。为避免导入 app 触发认证初始化，使用 AST 提取目标定义，不启动 Web 服务。结果如下：

```text
active_rate_limit_buckets 1500
missing_sub_token_grants_access True
security_response_sensitive_keys ['session_secret', 'admin_password_hash']
signed_future_other_user_token_accepted True
config_temp_mode_before_replace ['0o644']
config_final_mode 0o600
healing_flag_after_constructor_failure True
group_non_admin_callback_reaches_reip True
```

这些检查确认函数行为，不能替代浏览器 XSS 测试、真实 TLS 拦截测试、完整 HTTP 中间件验证和云平台集成验证。本次没有从真实配置读取或打印任何秘密，也没有运行仓库原有可能带副作用的全套测试。

## 6. 可追溯源码与外部依据

全部行号对应固定提交。核查时使用以下链接，避免 main 后续变化：

- [app.py](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/app.py)
- [auth_mgr.py](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/auth_mgr.py)
- [sentinel_core.py](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/sentinel_core.py)
- [前端](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/static/index.html)
- [Mesh](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/mesh_mgr.py)
- [证书同步](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/cert_sync_mgr.py)
- [Telegram](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/bot_mgr.py)
- [订阅引擎](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/sub_engine.py)
- [安装器](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/scripts/install.sh)
- [服务管理](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/service_mgr.py)
- [路径](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/paths.py)
- [测试沙箱](https://github.com/imprprpr/vpsentinel/blob/b7be8626a81b1ccb1bd39a9b5773becaa1417862/tests/sandbox.py)

安全公告在 S13 给出维护者原始链接。本报告没有把 Host 伪装、隐蔽路径或静态界面可见性当成鉴权；也没有把拥有管理员权限后能配置 hook 当成匿名命令执行漏洞。
