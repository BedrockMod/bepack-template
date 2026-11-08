# bepack-template

整合包作者模板，采用 bepack v1。仓库已包含严格 JSON Schema、离线工程校验、五项发布资产校验、Tag 发布流水线和严格 VirusTotal 扫描门禁；真实发布仍需要作者提供真实 runtime catalog，并配置外部 GitHub App / VirusTotal Secrets。

## 开始使用

1. Fork 本仓库或克隆为作者工程；GitHub 的“模板仓库”开关仍需仓库管理员配置。
2. 修改 `bepack.json` 中的包 ID、名称、作者、描述和作者许可。`example.my-pack` 是示例 ID，发布前必须替换。
3. 添加依赖或覆盖内容，并维护 `versions/stable.json` 的确切版本选择；runtime catalog 与依赖元数据必须是真实来源，不能手填猜测的兼容性。
4. 使用 Node.js 22+ 执行 `npm ci --ignore-scripts`、`npm test`、`npm run validate`。离线通过不表示可发布。
5. 配置发布前置条件（见下文），在真实依赖与兼容数据齐全后再推送与清单版本一致的 `v<version>` Tag。

## 发布前置条件

| 配置 | 位置 | 作用 |
|---|---|---|
| `VT_API_KEY` | 作者仓库 Actions Secret | 仅 scan job 可见；缺失时发布失败关闭 |
| `VT_UPLOAD_CONSENT=true` | 作者仓库 Actions Variable | 明确同意把最终包及可执行依赖送 VirusTotal 扫描；不设置则 preflight/scan 失败 |
| `BEPACK_RUNTIME_CATALOG_PATH` | 作者仓库 Actions Variable | 指向本仓库内已 pin 的 runtime catalog 文件；build 只读取该文件，缺失时失败关闭 |
| `BEPACK_RUNTIME_CATALOG_SHA256` | 作者仓库 Actions Variable | 外部固定的 64 位小写 SHA-256；校验完整 catalog 文件原始字节，不使用 catalog 自报摘要代替 |
| 真实 runtime catalog | 由平台适配器或作者仓库提供 | frozen build 解析真实游戏/加载器兼容数据；发布流水线不生成兼容性 |
| 官方 GitHub App（可选） | 官方侧安装到作者仓库 | 接收 Release 事件并通知 registry；未配置时显示“已发布，尚未收录” |

**当前外部状态：上述 Secret、Variable、GitHub App、registry bridge 尚未在本模板仓库配置或部署。** 仓库中的工作流与脚本就绪，不代表已在真实仓库启用。`GITHUB_TOKEN` 只用于本仓库 Release 读写，不用于跨仓库通知；不要把 registry 写凭证放进模板。

## 发布流水线

- `.github/workflows/pack-check.yml`：PR、main push、手动执行离线校验；不接触发布 Secret。
- `.github/workflows/pack-release.yml`：仅 `v*` Tag 或针对既有 Tag 的手动重试；按 preflight → build → scan → publish → notify 分 job。scan 只拿 VT Secret，publish 只拿 `contents: write`，两者不共享凭据。
- `scripts/bepack-release.mjs`：本地可单独执行各阶段；`verify-assets` 可供工坊/registry 辅助校验五项资产。

发布资产固定为：

```text
<pack-id>-<version>.bepack
<pack-id>-<version>.bepack.sha256
bepack.json
bepack-release.json
scan-report.json
```

缺 VT 配置、扫描未完成、恶意/可疑检出、资产摘要不一致、Tag 与版本不一致、同版本已公开但字节不同，都会失败；已公开 Release 不会被覆盖。扫描报告只记录某一时刻的观测，不声称“无恶意软件”。

## 当前限制

- 发布 CLI 通过 `node scripts/bepack.mjs build --project DIR --output DIR --frozen --runtime-catalog FILE --runtime-catalog-sha256 HEX` 子进程调用共用工具；可透传 `--generated-at`、`--metadata-dir`、`--staging-dir`。output 目录只允许一个 `<pack-id>-<version>.bepack`，元数据和 staging 不得混入发布输出。
- runtime catalog 文件及其外部可信 SHA-256 必须同时提供（`BEPACK_RUNTIME_CATALOG_PATH` / `BEPACK_RUNTIME_CATALOG_SHA256` 或对应 CLI 参数）。SHA-256 绑定完整 catalog 原始字节，必须来自维护者审核并固定的独立配置；catalog 自报的 `source.sha256` 仅是上游来源证据，不能代替外部信任根。真实 catalog 提供者尚未落地，测试 fixture 不能用作生产 catalog。
- 没有真实 Git Tag、Release、VirusTotal 扫描、registry 收录的端到端验收；发布模块测试全部使用本地 mock 和 fixture。
- 模板骨架尚未确定开源许可；默认作者许可为限制性 `LicenseRef-Pack`，发布前必须确认或替换。
- 空工程只是草稿，不能直接发布，也不代表与所有游戏版本兼容。

详见 [作者指南](docs/作者指南.md)、[发布与故障处理](docs/发布与故障处理.md) 和 [离线校验工具](tools/bepack-tool/README.md)。完整协议和仓库设计保存在 CGL 主工程 `docs/` 中。
