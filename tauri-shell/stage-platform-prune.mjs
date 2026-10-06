'use strict';
// 平台原生 payload 裁剪（stage-resources.mjs 装配期使用）。
// 独立模块：stage-resources.mjs 无 main guard，import 即执行全量装配，
// 纯函数放这里供 node:test 直接导入。
import { existsSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';

const LINUX_ELF_MACHINES = {
  x64: 62,
  arm64: 183,
};

export function assertSupportedStageArch(arch) {
  if (arch !== 'x64' && arch !== 'arm64') {
    throw new Error(`[stage] 不支持目标架构: ${arch}（仅支持 x64/arm64）`);
  }
}

export function isLinuxElfForArch(file, arch) {
  const machine = LINUX_ELF_MACHINES[arch];
  if (machine === undefined) return false;
  try {
    const data = readFileSync(file);
    return data.length >= 20
      && data[0] === 0x7f && data.subarray(1, 4).toString('ascii') === 'ELF'
      && data[4] === 2 && data[5] === 1
      && data.readUInt16LE(18) === machine;
  } catch {
    return false;
  }
}

export function pruneLinuxPayloads(dir, arch) {
  assertSupportedStageArch(arch);
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      pruneLinuxPayloads(file, arch);
      if (readdirSync(file).length === 0) rmSync(file, { recursive: true, force: true });
      continue;
    }
    if (!entry.isFile()) continue;
    if (/\.(?:exe|dll)$/i.test(entry.name)
      || (/\.node$/i.test(entry.name) && !isLinuxElfForArch(file, arch))) {
      rmSync(file, { force: true });
    }
  }
}

export function pruneNonLinuxPrebuilds(dir, arch) {
  assertSupportedStageArch(arch);
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const child = path.join(dir, entry.name);
    if (entry.name === 'prebuilds') {
      for (const platformDir of readdirSync(child, { withFileTypes: true })) {
        if (platformDir.isDirectory() && platformDir.name !== `linux-${arch}`) {
          rmSync(path.join(child, platformDir.name), { recursive: true, force: true });
        }
      }
    } else {
      pruneNonLinuxPrebuilds(child, arch);
    }
  }
}

/** 删除 node-addon-system 的 musl 变体（glibc 发行版里不可达）。
 * 该包同时分发 `bin/glibc/system.node` 与 `bin/musl/system.node`，运行时按
 * `process.report.header.glibcVersionRuntime` 二选一（内核 native/system
 * packages/entry/src/flock.ts）。发行目标是 glibc 的 deb/AppImage，musl 那份
 * 永远不可达，却是静态链接的 .node：linuxdeploy 对它调 ldd 会直接 abort
 * （`Failed to run ldd: exited with code 1`），AppImage 打包整体失败。
 * `pruneMuslPackages` 只看包名里的 linuxmusl 字样，命中不了这个子目录。 */
export function pruneMuslNodeAddonBinaries(nodeModules) {
  const scope = path.join(nodeModules, '@deepseek-ai');
  if (!existsSync(scope)) return;
  const pruned = [];
  for (const entry of readdirSync(scope, { withFileTypes: true })) {
    if (entry.isDirectory() && /^node-addon-system-linux-/.test(entry.name)) {
      const packageDir = path.join(scope, entry.name);
      const glibc = path.join(packageDir, 'bin', 'glibc', 'system.node');
      if (!existsSync(glibc)) {
        throw new Error(`[stage] ${entry.name} 缺少 glibc/system.node，无法安全剔除 musl 变体`);
      }
      rmSync(path.join(packageDir, 'bin', 'musl'), { recursive: true, force: true });
      pruned.push(entry.name);
    }
  }
  if (pruned.length) console.log(`[stage] 已剔除 musl 变体：${pruned.join(', ')}`);
}

/** ELF 魔数判断（前 20 字节足够取 e_machine）。 */
function isElfBuffer(data) {
  return data.length >= 20 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46;
}

/** audit-rpm-package.mjs 的不可达载荷正则（musl 段 / .exe / .dll）。
 * RPM 文件列表连空目录一起列出：剪掉 musl 变体文件后残留的空 musl_x64
 * 目录同样会被整包拒绝，所以这里按名字整目录剔除。 */
const MUSL_NAME_RE = /^(?:musl(?:[_-]|$)|linuxmusl)/i;

/** 删除 Linux 打包会炸或审计会拒的外来载荷：
 * 1. 非目标架构 ELF（full-pack 种子里的 darwin/arm 预构建）；
 * 2. musl ELF 变体——嵌套 node_modules 里的
 *    @koromix/koffi-linux-x64/musl_x64/koffi.node（NEEDED libc.musl-x86_64.so.1）
 *    顶层 rmSync 只管提升副本，嵌套副本全部漏网，2026-10-06 CI 实测 linuxdeploy
 *    在 AppImage 阶段 abort："Could not find dependency: libc.musl-x86_64.so.1"；
 *    上游 pruneLinuxPayloads 只查 ELF 架构位，静态 musl 恰好也是合法 x64 ELF，
 *    天生检不出来，必须按字节扫 NEEDED/INTERP；
 * 3. Windows PE（.exe/.dll）——Linux 永不加载，且审计正则整包拒绝；
 *    唯一来源是 vendor/pnpm/dist/vendor/fastlist-*.exe（pnpm 的 win32 进程
 *    枚举器），官方 full-pack 种子实测 0 个 PE 文件；
 * 4. musl 命名的目录/文件（含剪枝后残留的空 musl_x64 目录）与剪枝产生的
 *    空目录（audit 按路径段匹配，空目录也会出现在 rpm -qlp 里）。
 * 调用方须扫整棵 staged 树：vendor/pnpm 在 nmDest/assets 范围之外，
 * 2026-10-06 run 37445876795 full+lite 双双死在 Audit RPM 步骤即此漏网。 */
export function pruneForeignElfBinaries(dir, arch) {
  const expectedMachine = arch === 'arm64' ? 0xb7 : 0x3e; // EM_AARCH64 / EM_X86_64
  const pruned = [];
  const visit = (d) => {
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const p = path.join(d, entry.name);
      if (MUSL_NAME_RE.test(entry.name)) {
        rmSync(p, { recursive: true, force: true });
        pruned.push(path.relative(dir, p));
        continue;
      }
      if (entry.isDirectory()) {
        visit(p);
        try {
          if (readdirSync(p).length === 0) rmSync(p, { recursive: true, force: true });
        } catch { /* 并发删除竞态，忽略 */ }
        continue;
      }
      if (!entry.isFile()) continue; // 符号链接不动（lstat 语义，不跟随）
      if (/\.(?:exe|dll)$/i.test(entry.name)) {
        rmSync(p, { force: true });
        pruned.push(path.relative(dir, p));
        continue;
      }
      const candidate = /\.(?:node|bare|so)$/i.test(entry.name) || /musl/i.test(p);
      if (!candidate) continue;
      let data;
      try {
        data = readFileSync(p);
      } catch {
        continue;
      }
      if (!isElfBuffer(data)) continue;
      const machine = data[18] | (data[19] << 8);
      const text = data.toString('latin1');
      const musl = text.includes('libc.musl') || text.includes('ld-musl');
      if (musl || machine !== expectedMachine) {
        rmSync(p, { force: true });
        pruned.push(path.relative(dir, p));
      }
    }
  };
  visit(dir);
  if (pruned.length) {
    console.log(`[stage] 已剔除 musl/外来 ELF/Windows PE（${arch} glibc 发行不可达）：${pruned.join(', ')}`);
  }
}

/** 是否为 64 位小端 Mach-O（.node 在 macOS 上为 Mach-O dylib）。
 * 假设：npm 生态的 darwin-arm64 .node 均为 thin（单架构）dylib；若未来出现 FAT/universal 二进制会被误删，届时需扩展魔数识别。 */
export function isMachO(file) {
  try {
    const data = readFileSync(file);
    return data.length >= 4
      && data[0] === 0xcf && data[1] === 0xfa && data[2] === 0xed && data[3] === 0xfe;
  } catch {
    return false;
  }
}

export function pruneDarwinPayloads(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      pruneDarwinPayloads(file);
      if (readdirSync(file).length === 0) rmSync(file, { recursive: true, force: true });
      continue;
    }
    if (!entry.isFile()) continue;
    if (/\.(?:exe|dll)$/i.test(entry.name) || (/\.node$/i.test(entry.name) && !isMachO(file))) {
      rmSync(file, { force: true });
    }
  }
}

export function pruneNonDarwinPrebuilds(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const child = path.join(dir, entry.name);
    if (entry.name === 'prebuilds') {
      for (const platformDir of readdirSync(child, { withFileTypes: true })) {
        if (platformDir.isDirectory() && platformDir.name !== 'darwin-arm64') {
          rmSync(path.join(child, platformDir.name), { recursive: true, force: true });
        }
      }
    } else {
      pruneNonDarwinPrebuilds(child);
    }
  }
}
