# 第三方许可声明

当前示例整合包没有打包第三方游戏内容。添加依赖或文件后，作者必须补齐来源、许可证及必要的许可材料。
不得用本文件代替 bundled 依赖的许可校验。

## 开发工具材料（不进入整合包 payload）

- Unicode CaseFolding 17.0.0：工具使用默认完整大小写折叠数据；原文和 Unicode License V3 保留在 tools/bepack-tool/src/data 中。来源和固定 SHA-256 见工具 README。该数据不授予模板其余代码任何默认开源许可。
- npm 工具依赖：Ajv、spdx-expression-parse 及其传递依赖由 package-lock.json 固定。安装时的授权文本位于各依赖包 LICENSE 文件；未来分发独立工具必须随发行保留全部必要声明，不能用作者整合包 LicenseRef-Pack 替代。
