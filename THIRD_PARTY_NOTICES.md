# 第三方许可声明

当前示例整合包没有打包第三方游戏内容。添加依赖或文件后，作者必须补齐来源、许可证及必要的许可材料。
不得用本文件代替 bundled 依赖的许可校验。

## 开发工具材料（不进入整合包 payload）

- Unicode CaseFolding 17.0.0：工具使用默认完整大小写折叠数据；原文和 Unicode License V3 保留在 tools/bepack-tool/src/data 中。来源和固定 SHA-256 见工具 README。该数据不授予模板其余代码任何默认开源许可。
- npm 工具依赖：Ajv、spdx-expression-parse 及其传递依赖由 package-lock.json 固定。安装时的授权文本位于各依赖包 LICENSE 文件；未来分发独立工具必须随发行保留全部必要声明，不能用作者整合包 LicenseRef-Pack 替代。

## 发布流水线外部服务（不进入整合包）

- GitHub Actions / GitHub REST API：发布流水线调用 GitHub 托管服务创建 Release、上传资产和查询 Tag/提交。工作流使用官方 `actions/checkout`、`actions/setup-node`、`actions/upload-artifact`、`actions/download-artifact`，各自按其仓库许可证使用；第三方 Action 固定到官方 Tag 对应 commit。GitHub 服务条款和作者仓库权限同样适用。
- VirusTotal：仅在作者配置 `VT_API_KEY` 并显式设置 `VT_UPLOAD_CONSENT=true` 时，发布流水线才会把最终 `.bepack` 及计划中的可执行依赖上传到 VirusTotal 分析。上传意味着样本会提交给第三方服务，作者必须确认拥有再分发/上传权利，并遵守其服务条款与配额。扫描报告只记录服务返回的观测，不构成“无恶意软件”保证。
- 官方 registry 通知：正式设计使用官方 GitHub App 接收 Release 事件，再由 registry 侧独立复验；模板仓库不包含官方 App 私钥或 registry 写凭证。当前 bridge 服务尚未部署，未配置时 notify 阶段明确 skipped。

发布工具源码本身尚未以独立 `tool-v*` 二进制发行；`bepack-release.json` 中的工具身份是源码清单摘要，不是第三方二进制再分发。
