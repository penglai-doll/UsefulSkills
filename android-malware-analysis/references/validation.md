# Skill 验证

在修改 APK 分析 skill 后，至少完成下面这组最小验证。

## 1. 结构校验

```bash
python3 /Users/penglai/.codex/skills/.system/skill-creator/scripts/quick_validate.py /absolute/path/to/android-malware-analysis
```

预期：

- 输出 `Skill is valid!`

## 2. Ledger 脚本自测

```bash
python3 scripts/skill_ledger.py self-test
python3 -m unittest tests/test_skill_ledger.py
python3 -m unittest tests/test_noise_log.py
python3 -m unittest tests/test_callback_refinement.py
```

预期：

- `self-test` 输出 `Skill ledger self-test passed.`
- 单元测试通过，至少覆盖：
  - 默认 ledger 路径指向 skill 根目录下的 `skill-ledger.json`
  - 新问题会被记录
  - 同 key 重复出现不会膨胀成长日志
  - 超过 20 条 active lessons 后会自动压缩
  - `noise-log.json` 会生成到 `cache/<sample-name>/`
  - 被抑制的 URL / 域名 / SDK key 候选会进入调试日志而不是最终报告正文
  - 最终采信结果会把公共服务 host 和说明页 URL 从 IOC 里压掉，并保留到噪声日志

## 3. 元数据一致性

人工确认这些点：

- `SKILL.md` 的 frontmatter 明确说明“仅在 APK 分析时使用”
- `agents/openai.yaml` 的 `short_description` 和 `default_prompt` 没有漂移到通用 Android 开发场景
- `SKILL.md`、`workflow.md`、`ledger.md`、`gotchas.md` 之间的命令和路径一致

## 4. 护栏回看

人工确认这些边界仍然成立：

- 默认静态分析
- 不执行样本，不安装到设备或模拟器
- 不把公开域名或第三方库 URL 直接写成最终 IOC
- 不把无厂商上下文的通用 `appkey` / `appid` / `token` 当成可调证结论

## 5. 输出目录检查

人工确认这些路径规则仍然成立：

- 默认输出根目录是样本当前目录
- 最终报告落在 `报告/<sample-name>/`
- 中间产物落在 `cache/<sample-name>/`
- `analysis.json`、`callback-config.json`、`noise-log.json` 和 `icons/` 不会混进最终报告目录
