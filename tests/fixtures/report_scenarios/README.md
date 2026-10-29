# 报告合成测试场景

这些场景只用于版面与规模验证。所有合成报告都标明“合成测试数据”，不代表客户环境。

`generate.py` 从已验收冻结 run 的规范化属性结构派生测试事实。小型 `seed.json` 只保留 140 个数值、布尔和 null 原型，不含真实名称、IP 或对象 ID；五套合成场景仅依赖该随脚本种子，无需原机器的客户 JSON。所有对象名称、对象键、IP、路径均重新生成；不修改冻结 JSON、数据库或报告。IP 只使用 RFC 5737 文档网段。

生成过程使用当前未修改的 `RuleExecutor`、规则 YAML、`ReportContextBuilder` 和 `ReportDataFactory`。检查结果、等级和统计由规则实际计算，不手工注入结果。

授权输入通过本地 SDK 响应替身构造实体分配证据：vCenter 有明确 Never 字段，主机有明确到期字段，实体 ID 和作用域均绑定本场景的合成对象。它只生成合成输入事实，不连接 SDK、不复制真实授权、不注入检查通过结果；授权状态转换复用产品 `license_state`，该依赖也计入缓存指纹。

```powershell
.venv\Scripts\python.exe -B tests/fixtures/report_scenarios/generate.py --scenario all
```

默认缓存与 manifest 输出到 `out/report-scenarios`，不提交大数据文件。可通过 `--output` 指定另一个隔离目录；禁止写入真实报告目录。每次生成前检查磁盘剩余不少于 100 GiB。

可导入接口：`load_scenario(name, output_root=None) -> (ReportData, context)`。名称为 `minimal`、`large`、`many_problems`、`heterogeneous`、`boundary`。显式选择 `frozen` 才会使用本机只读来源，可传 `frozen_loader_path=` 或环境变量 `VSTACKLENS_FROZEN_REPORT_LOADER`；来源缺失时明确报错，不回退成空数据。

缓存指纹覆盖生成器、种子、规则 YAML 以及实际规则执行、规范化、数据库、证据、报告 context/model/共享展示代码的文件字节，因此未提交的代码变化同样会失效。缓存还核对已完成 manifest 与数据库 SHA；未完成数据库不得被另一进程当成有效数据读取。

场景规模：

| 场景 | 集群 | 主机 | 虚拟机 | 数据存储 | 重点 |
|---|---:|---:|---:|---:|---|
| minimal | 1 | 1 | 10 | 2 | 无 vSAN，客户检查全部通过，问题为零 |
| large | 8 | 64 | 1500 | 20 | 十类命中，去重问题对象大于 1000；ISO、快照各至少 300 对象 |
| many_problems | 4 | 16 | 120 | 8 | P1/P2/P3，多集群，证书过期与高存储水位 |
| heterogeneous | 3 | 6 | 60 | 4 | 三个集群分别为 ESXi 6.7/7.0/8.0，ESA 仅挂 8.0 主机且无磁盘组；标准交换机，维护、断开及缺字段 |
| boundary | 2 | 2 | 20 | 4 | 长中文、长路径、特殊字符、零 VM 集群和单对象类别 |

每个版本缓存目录中的 `manifest.json` 记录实际规则统计、问题类别及对象数、原始状态分布、规则/生成器指纹及构建耗时。“全部通过”指客户 P1–P3 适用且有明确判断的检查全部通过；不适用项仍保持不适用，不改写成通过。
