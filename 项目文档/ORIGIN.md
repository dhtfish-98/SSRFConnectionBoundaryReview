# 来源与独立范围

本项目是 `dhtfish98` 新写的本地连接边界实验，没有修改、复制或打包任何目标服务源码。受控 DNS 只在 `127.0.0.1` 接收 A/AAAA 查询；两个 HTTP 端点分别绑定 `127.0.0.1` 与 `::1`，使用合成标记，不含真实内部服务或密钥。

OWASP SSRF 防御指导强调：URL/协议要按允许规则处理，DNS 返回的所有 A/AAAA 地址要分类，并把连接固定到已验证地址；单独的预检查不能消除 DNS rebinding。自动重定向也会绕过原目标的校验。本项目据此实现每一跳、每次重试重新解析，连接前检查全部候选地址，并在发送 HTTP 请求前检查实际 socket 对端。

参考来源：

- [OWASP Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 A10:2021 Server-Side Request Forgery](https://top10.owasp.org/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

本项目与 RedirectCredentialBoundary 的边界不同：后者研究跨来源重定向时凭据头是否被剥离；这里研究**目标地址与实际连接对端**是否符合策略，不发送授权头、不判断凭据转发。没有发现或声称任何第三方产品漏洞。授权任务、保障措施影响、真实部署和 Anthropic CVP 资格均 **OPEN**。
