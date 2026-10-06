# SSRFConnectionBoundaryReview v0.1.0

本版本的新写实现由 `dhtfish98` 署名；运行只使用 Python 标准库，构建依赖权利与 OWASP 参考来源如[权利说明](NOTICE.md)所列。

本版本的验证流程运行源码、解包 sdist 和隔离 wheel 的 14 项真实回环单测，并运行源码和 wheel 的十组实验。总时限覆盖慢滴响应、跨重定向和跨重试；具体结果应以对应运行在源码目录外中央 `Build` 生成的 `validation.json`、原始日志、精确提交上的 CI 和实际发行附件为准。版本号本身不证明 GitHub 已公开发行。

真实授权任务、保障措施影响、生产环境能力、第三方漏洞以及 Anthropic CVP 资格与批准仍 **OPEN**。独立复核只对其明确冻结的源码和包字节有效。
