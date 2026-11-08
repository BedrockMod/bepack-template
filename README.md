# bepack-template

整合包作者模板，采用 bepack v1。已提供严格 JSON Schema 和离线工程校验工具；尚不具备自动打包发布能力。

## 开始使用

1. Fork 本仓库或克隆为作者工程；GitHub 的“模板仓库”开关仍需仓库管理员配置。
2. 修改 `bepack.json` 中的包 ID、名称、作者、描述和作者许可。`example.my-pack` 是示例 ID，发布前必须替换。
3. 添加依赖或覆盖内容，并维护 `versions/stable.json` 的确切版本选择。
4. 使用 Node.js 22+ 执行 `npm ci --ignore-scripts`、`npm test`、`npm run validate`。离线通过不表示可发布。
5. 后续解析/锁定、构建和可信发布工作流接入后，完成真实兼容验证和扫描，再推送与清单版本一致的 Tag。

## 默认工程

- `mods-only` 模式，所有游戏版本字段均为 `null`，不询问或绑定游戏版本。
- 仅启用 Windows x86_64 客户端目标，加载器为 `none`。这不代表已适配 LL 或任何第三方客户端。
- 依赖及内容为空：仅为草稿，不能直接发布，不代表与所有游戏版本兼容。
- 目录中的 `.gitkeep` 仅用于跟踪空目录，不得进入发布包。
- 默认作者许可为限制性 `LicenseRef-Pack`，请明确选择自己的许可；模板骨架尚未确定开源许可，不作默认授权。

## 尚未实现

网络依赖解析、兼容锁定和 lock Schema、安全打包、安装器、工具签发与摘要固定、GitHub Actions、VirusTotal 扫描和真实端到端验证。此阶段不提供伪工作流、虚构工具下载地址或零值 lock。不要据此创建正式发布 Tag。

本地工具的命令、Schema 复用、退出码和未检查项见 [离线校验工具](tools/bepack-tool/README.md)。完整协议和仓库设计保存在 CGL 主工程 docs 中；当前模板不是完整打包标准的替代文档。

详见 [作者指南](docs/作者指南.md) 和 [发布与故障处理](docs/发布与故障处理.md)。
