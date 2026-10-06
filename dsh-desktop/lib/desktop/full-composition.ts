'use strict';

// 随包完整离线包（assets/full-pack）消费层。
//
// 背景：官方 v6.0.0 Windows full 发行包在 dsh-desktop/assets/full-pack 下携带
// 一份离线全量 profile 种子（composition.json 清单 + profile-seed/ 预装闭包：
// 插件、皮肤与依赖的 node_modules，平台无关）。首启建档时由 profile.ts 的
// ensureDesktopProfileInit 调 seedFullProfile 原子播种进新建的 web-desktop
// profile，并写入 .eac-full-ownership.json 所有权回执。
//
// 最简内核收敛（ADR 0006）期间这一层未随源码树保留；本文件按官方 v6.0.0
// 发行包内的编译产物 lib/desktop/full-composition.js（core 9bc1a2ea /
// pack 15672c6）等价移植为 TypeScript，供 Linux full 打包变体恢复同等能力。
// lite 形态不携带 assets/full-pack 时 readComposition 返回 null，全部入口
// 自动退化为无 full-pack 的既有行为。

import fs = require('node:fs');
import path = require('node:path');
import { APP_ROOT } from './runtime-paths';

export interface FullCompositionManifest {
  schemaVersion: number;
  profile: string;
  coreCommit?: string;
  packCommit?: string;
  dpxCommit?: string;
  managedPackages: string[];
}

interface FullOwnershipReceipt {
  schemaVersion: number;
  profile: string;
  managedPackages: string[];
}

interface PatchRow {
  id?: unknown;
  name?: unknown;
}

// 窄签名消费 yaml（companion-sync 已静态依赖 yaml，此处同源）。
const yamlModule = require('yaml') as {
  parseDocument(text: string, opts?: { logLevel?: string }): { errors: unknown[]; toJSON(): unknown };
};

export function readComposition(root: string = APP_ROOT): FullCompositionManifest | null {
  const file = path.join(root, 'assets', 'full-pack', 'composition.json');
  if (!fs.existsSync(file)) return null;
  const value = JSON.parse(fs.readFileSync(file, 'utf8')) as FullCompositionManifest;
  if (value.schemaVersion !== 1 || value.profile !== 'web-desktop' || !Array.isArray(value.managedPackages)) {
    throw new Error('Invalid full EAC composition manifest');
  }
  return value;
}

// Only a new, atomically seeded profile receives pack ownership. Existing
// profiles remain untouched, and a missing/invalid receipt never bypasses
// legacy retirement.
export function seedFullProfile(profileDir: string, root: string = APP_ROOT): boolean {
  const composition = readComposition(root);
  if (!composition || fs.existsSync(path.join(profileDir, 'package.json'))) return false;
  const safeMode = path.join(path.resolve(profileDir, '..', '..'), 'guard', 'safe-mode.json');
  if (fs.existsSync(safeMode)
    && (JSON.parse(fs.readFileSync(safeMode, 'utf8')) as { active?: boolean }).active === true) {
    return false;
  }
  const seed = path.join(root, 'assets', 'full-pack', 'profile-seed');
  if (!fs.existsSync(path.join(seed, 'package.json')) || !fs.existsSync(path.join(seed, 'node_modules'))) {
    throw new Error('Full EAC offline profile seed is incomplete');
  }
  if (fs.existsSync(profileDir) && fs.readdirSync(profileDir).length) {
    throw new Error('Refusing to overwrite a nonempty uninitialized profile');
  }
  const staging = profileDir + '.full-seed-' + process.pid;
  if (fs.existsSync(staging)) throw new Error('Interrupted full profile seed exists: ' + staging);
  fs.mkdirSync(path.dirname(profileDir), { recursive: true });
  fs.cpSync(seed, staging, { recursive: true, dereference: true });
  fs.writeFileSync(path.join(staging, '.eac-full-ownership.json'), JSON.stringify({
    schemaVersion: 1,
    profile: composition.profile,
    managedPackages: composition.managedPackages,
  }, null, 2) + '\n');
  if (fs.existsSync(profileDir)) fs.rmdirSync(profileDir);
  fs.renameSync(staging, profileDir);
  return true;
}

export function bindFullHostClosure(home: string, root: string = APP_ROOT): void {
  const modules = path.join(root, 'node_modules');
  const shared = path.join(home, 'profiles', 'node_modules');
  for (const entry of fs.readdirSync(modules, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const names = entry.name.startsWith('@')
      ? fs.readdirSync(path.join(modules, entry.name)).map((name) => entry.name + '/' + name)
      : [entry.name];
    for (const name of names) {
      const source = path.join(modules, ...name.split('/'));
      const target = path.join(shared, ...name.split('/'));
      if (!fs.existsSync(path.join(source, 'package.json')) || fs.existsSync(target)) continue;
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.symlinkSync(source, target, 'junction');
    }
  }
}

export function packOwnsPatchEntry(profileDir: string, id: string, text: string, root: string = APP_ROOT): boolean {
  if (!readComposition(root)) return false;
  try {
    const document = yamlModule.parseDocument(text, { logLevel: 'silent' });
    if (document.errors.length) return false;
    const rows = document.toJSON();
    return Array.isArray(rows) && rows.some((row) => {
      const entry = row as PatchRow | null;
      if (!entry || typeof entry !== 'object') return false;
      return entry.id === id && typeof entry.name === 'string' && packOwnsPackage(profileDir, entry.name, root);
    });
  } catch {
    return false;
  }
}

export function packOwnsPackage(profileDir: string, name: string, root: string = APP_ROOT): boolean {
  const composition = readComposition(root);
  if (!composition || !composition.managedPackages.includes(name)) return false;
  try {
    const receipt = JSON.parse(fs.readFileSync(path.join(profileDir, '.eac-full-ownership.json'), 'utf8')) as FullOwnershipReceipt;
    if (receipt.schemaVersion !== 1 || receipt.profile !== composition.profile || !receipt.managedPackages.includes(name)) {
      return false;
    }
    const manifest = JSON.parse(fs.readFileSync(path.join(profileDir, 'package.json'), 'utf8')) as { dependencies?: Record<string, string> };
    return typeof manifest.dependencies?.[name] === 'string';
  } catch {
    return false;
  }
}
