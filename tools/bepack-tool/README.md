# bepack-tool：离线工程校验

## 需求

读取 bepack.json 和其 version_set 指向的版本组合，输出可定位错误；不修改作者工程、不发起网络请求。Node.js >=22。当前不是打包器或发布工具。

在仓库根目录执行：

```sh
npm ci --ignore-scripts
npm test
npm run validate
node scripts/bepack.mjs validate --project /path/to/project --report /path/to/new-report.json
```

报告文件必须不存在，禁止覆盖已有文件。返回 0 表示本阶段检查通过，2 表示工程无效/参数错误，1 表示工具或报告输出失败。工程报告在 stdout，执行/参数错误在 stderr。

## 架构

- schemas/bepack.schema.json、schemas/version-set.schema.json：Draft 2020-12，可各自独立离线加载。$defs 保持一致；扩展只允许 extensions 命名空间。Schema 单独校验不代替严格解析和语义检查；URI format 必须启用断言。
- src/strict-json.mjs：无 BOM、严格 UTF-8、重复键（含转义等价键）、根对象、字节/深度限制。
- src/paths.mjs：安全路径、Unicode 默认完整 case folding 后 NFC、链接/硬链接/特殊文件拒绝、跨引用碰撞和预算。
- src/validate.mjs：validateProject(directory) 返回结构化报告。校验实际组合合并后的四模式、目标/依赖/内容引用、版本要求和选择、许可声明、direct 映射与内容目的地冲突等。
- test：严格解析、安全路径、四模式、版本/许可/内容、错误定位、CLI 行为和审查回归。

报告的 scope=offline-project、release_checked=false。diagnostics 中的 file 和 field（JSON Pointer）供编辑器定位；code 是机器标识，message 不能作为前端翻译 key。

默认 JSON 各 4 MiB、深度 128；共享文件扫描 100000 文件、单文件 8 GiB、总计 32 GiB、最多 200000 路径条目。重复精确引用仅累计一次；别名祖先也拒绝。

共享 Schema/CLI 供未来工坊、发布 CI 和 registry 复用。registry 必须从固定可信工具提交调用，不执行作者自带代码，也不能把离线 valid=true 当作发布资产复验。

### Unicode 材料

使用 Unicode 17.0.0 默认完整大小写折叠，读取 C/F 项，排除 T 项，不使用 toLowerCase/toUpperCase 近似算法。文件随工具提交，运行时校验数据 SHA-256。

- 数据来源：https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt
- 数据路径：src/data/CaseFolding-17.0.0.txt
- SHA-256：ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183
- 许可来源：https://www.unicode.org/license.txt
- 许可路径：src/data/UNICODE-LICENSE.txt
- 许可 SHA-256：e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96

原始版权/许可保持完整。npm 依赖在 package-lock.json 固定，其各自授权见安装包 LICENSE；工具源码的整体开源许可仍需权利人确定。

## 备注

未实施的检查在报告 unchecked 中显式列出：远程依赖解析/SSRF、运行时目录和兼容交集、MCBE 格式和世界引用、适配器配置白名单/原生布局、ZIP/lock 完整性、发布投影和扫描、安全安装事务。

本工具不生成 bepack.lock.json 或 .bepack；不支持 resolve、build、scan、publish；没有伪实现和跳过门禁选项。空模板是合法草稿，仍不可发布。路径静态检查不是消除 TOCTOU 的安装机制。后续先完成 resolve/lock/build，再接实际扫描和可信 Actions。