# Install Profiler — 迁移 / 安装说明

这是一个 **DeepSeek Harness bundle**（Host-only 插件），没有 npm 依赖、不需要编译，只做一件事：向当前 profile 注册一个名为 `install-profiler` 的技能。

## 1. 前置条件

- 目标 DSH 支持 bundle patch（`package.json` 里的 `dsh.bundle.patch`）和 `ctx.skills.register`
- 当前会话有 **Full access**，或允许对 `plugin_manager` 操作进行审批

## 2. 先把文件放到长期目录

解压这个 zip 到一个**不会被移动或删除**的目录，例如：

```
C:\Tools\dsh-install-profiler
```

> 重要：`install_bundle` 对本地目录采用 **link（链接）** 方式安装，不是复制。
> 装完之后这个目录必须保留；删掉或改名会导致插件失效（技能从目录中消失）。

解压后目录里应该直接是 `package.json`、`cordis.patch.yml`、`index.js`、`scripts\`、`skills\` 等，共 19 个文件。

## 3. 在目标 DSH 里安装

在目标 DSH 的会话中执行（把路径换成第 2 步的真实路径）：

```
plugin_manager action=install_bundle target=C:\Tools\dsh-install-profiler
```

成功返回类似：

```json
{ "application": "applied", "bundle": "@local/dsh-install-profiler", "version": "1.1.0", "warnings": [] }
```

`application: "applied"` 才表示生效；`restart-required` 表示需要重启 DSH。

## 4. 验证

任选其一：

```
plugin_manager action=list_plugins
```
应能看到 `@local/dsh-install-profiler` / 行 id `install-profiler`。

或（免审批）：

```
cordis_inspect_query platform=host provider=Config method=listConfigs input={"name":"@local/dsh-install-profiler"}
```
应返回 `patchId: "install-profiler"`（`status: "absent"` 是正常的，表示没有 Config 段）。

最直接的验证：技能目录里出现 `install-profiler`。

## 5. 用法

直接对 DSH 说：

- “给这个安装包做安装画像”（把安装包放进 workspace 或给路径）
- “这软件装完起不来，帮我查”
- “这个 MSI 会写哪些注册表、起哪些服务、日志在哪”

它会自动走：探工具 → 判型 → 解包 → 读 MSI 表/采运行态 → 出 `report.md` + `profile.json`；需要动态验证时再生成 `probe-plan.json`。

## 6. 关闭 / 开启 / 卸载

```
plugin_manager action=set_plugin target=install-profiler enabled=false
plugin_manager action=set_plugin target=install-profiler enabled=true
plugin_manager action=remove_bundle target=@local/dsh-install-profiler
```

关闭后技能立刻从会话目录消失；重新开启会重新读取 `skills\install-profiler\SKILL.md`，所以改内容后开关一次即可生效，不用重启。

## 7. 装到同一台机器的另一个 profile

在目标 profile 的会话里重复第 3 步即可（路径不变）。切换 profile 用：

```
dsh --profile <profile名>
```

## 8. 常见问题

| 现象 | 处理 |
|---|---|
| `already-installed` | 先 `remove_bundle`，再 `install_bundle` |
| 安装后技能不出现 | 确认 `application` 是 `applied`；检查会话是否有 Full access |
| 技能消失 | 源目录被移动/删除（link 方式安装），把它放回原路径或重新安装 |
| 脚本执行被策略拦截 | 技能里已统一用 `powershell -NoProfile -ExecutionPolicy Bypass -File …` 调用 |
| 解压后文件数不对 | 用 `Expand-Archive` 或 7-Zip 重新解压；应为 19 个文件 |

## 9. 内容清单

```
package.json / cordis.patch.yml / index.js
locale\en.json / locale\zh.json / icon.svg
skills\install-profiler\SKILL.md
skills\install-profiler\references\fault-playbook.md
skills\install-profiler\assets\report-template.md
skills\install-profiler\assets\profile.schema.json
scripts\probe-tools.ps1
scripts\detect-installer.ps1
scripts\export-msi-tables.ps1
scripts\collect-state.ps1
scripts\build-probe-plan.ps1
scripts\capture-snapshot.ps1
scripts\diff-snapshots.ps1
README.md
INSTALL.md
```
