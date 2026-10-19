import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SKILL_NAME = 'install-profiler'
const SKILL_DIR = join(dirname(fileURLToPath(import.meta.url)), 'skills', SKILL_NAME)

/**
 * Embedded skill provider: registering through `ctx.skills` puts the skill into
 * the profile-global skill layer, so every agent sees it in its catalog while
 * this row is enabled. Disabling the row disposes the registration and the
 * tool-skill consumer appends a replacement catalog without it.
 *
 * The SKILL.md body is read during `apply`, so editing it and toggling the row
 * picks up the new text without restarting Harness.
 */
export const inject = ['skills']

export function apply(ctx) {
  const content = readFileSync(join(SKILL_DIR, 'SKILL.md'), 'utf8')

  ctx.effect(() =>
    ctx.skills.register({
      name: SKILL_NAME,
      description:
        'Profile a Windows installer package (MSI, EXE-based, MSIX) before or after installing it: extract its default install layout, ' +
        'registry writes, services/drivers, scheduled tasks, config files, log locations and Event Log sources; mine a binary for ' +
        'registry paths, log paths and error templates when there is no MSI database; then turn that static map ' +
        'into a targeted dynamic probe (paths, registry keys, services, event IDs, Procmon filters), diff before/after snapshots, ' +
        'and diagnose install/startup/runtime faults with the mechanism behind each fix. ' +
        '安装包画像与故障排查：注册表、安装位置、服务、日志、事件源、配置项，静态画像驱动动态取证，以及故障定位与修复原理。',
      whenToUse:
        'The user supplies an application installer (or an already-installed app) and asks what it installs where, which registry keys, ' +
        'services, config files, logs or event sources it uses, why it fails to install/start/run, or how to fix and prevent such failures.',
      source: 'runtime',
      resourceBase: { kind: 'directory', path: SKILL_DIR },
      content,
    }),
  )
}
