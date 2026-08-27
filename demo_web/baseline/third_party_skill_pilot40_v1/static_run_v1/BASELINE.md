# 第三方 Skill 40 样本静态运行冻结

该目录保存 `2026-08-28-third-party-skill-pilot40-static-v1` 主运行及失败重检的可审计输出。样本内容不进入 Git；来源、提交、许可证、样本 ID 和树哈希由上级基线目录固定。

关键结果：38/40 完成，强标签恶意召回 100%、非正常召回 87.5%、正常误报率 12.5%、严格宏 F1 48.89%。两例 UNKNOWN 均在顺序重跑中稳定复现，根因为 frontmatter 缺少 `name` 和 YAML 语法错误。动态合格数为 0，未执行第三方脚本。

结果解释和规则边界见 `demo_web/docs/M8_THIRD_PARTY_SKILL_PILOT40_STATIC_REPORT.md`。
