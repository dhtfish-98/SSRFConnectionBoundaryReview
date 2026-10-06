# SSRFConnectionBoundaryReview v0.1.0

这是 `dhtfish98` 新写的**回环实验**：受控 UDP DNS 对合成 `*.lab.test` 名称逐次返回 `127.0.0.1` 或 `::1`；两个自有 HTTP 服务分别扮演允许目标与假内部目标。客户端逐跳、逐次重试重新解析 A/AAAA，拒绝任何不允许的答案，按已验证数字地址直连，并在发送 HTTP 请求前检查 socket 的实际对端地址及端口。同一次抓取共用 `total_timeout` 时限，慢速响应、重定向和重试不能各自重新获得完整时限；它适用于本项目的协作式网络组件，具体限制见[设计](DESIGN.md)。

实验区分两种策略：`PublicOnlyPolicy` 按公开地址及额外禁用网段分类，**正常阻止全部回环地址**；`LabOnlyPolicy` 只对明确列出的合成 `(名称, 127.0.0.1, 端口)` 开放回环例外，不能用于生产公网保护。演示脚本从不向公网解析或扫描，只绑定 `127.0.0.1` 和 `::1`。假内部端点只返回合成标记，没有真实内部资产。

从项目根目录运行版本验证，并把 `--build-root` 换成**源码目录外**的工作区中央 `Build` 的绝对路径；缓存、包、安装目录和收据均放在那里：

```sh
python3 scripts/run_validation.py --build-root /path/to/workspace/Build/验证/SSRFConnectionBoundaryReview-run1
```

每次验证使用新的中央 `Build` 子目录（例如把末尾改成 `SSRFConnectionBoundaryReview-run2`）；脚本拒绝项目源码目录内的输出路径，也拒绝覆盖非空目录，以保留上一轮证据。

版本验证覆盖源码、解包源码包及隔离安装 wheel 的各 14 项真实回环 socket 测试，以及源码和 wheel 的各十组实验；其中包括慢速响应、重定向和重试共用时限及连接后超时关闭测试。机器收据保存在所选中央 `Build` 目录的 `validation.json`，本地与托管运行的结果应分别核对，见[验证记录](VALIDATION.md)。公开发行状态以版本标签、对应的主分支与标签 CI、实际下载的附件哈希为准。其范围与 [RedirectCredentialBoundary](https://github.com/dhtfish-98/RedirectCredentialBoundary) 不同：该项目检查重定向时的凭据头，这里检查**目标 IP/端口与实际连接对端**；本实验不发送授权头。

参考 [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) 和 [OWASP A10:2021 SSRF](https://top10.owasp.org/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)。设计、排除范围及未验证事项见[设计](DESIGN.md)和[来源/权利](ORIGIN.md)。不声称任何第三方上游漏洞、生产防护效果或 Anthropic CVP 资格；真实授权高风险双用途任务、保障措施影响、申请身份与官方批准均 **OPEN**。
