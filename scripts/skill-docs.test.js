#!/usr/bin/env node
// skill-docs.test.js — SKILL.md 문서 컨벤션 테스트

const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..");
const SKIP = new Set([
  ".git", ".github", ".omc", "docs", "scripts",
  "packages", "python-packages", "node_modules",
]);

// 영문 또는 한국어 섹션 헤더 모두 허용
const REQUIRED_SECTIONS = [
  { en: "## What this skill does", ko: /^## 이 스킬이 하는 일/m },
  { en: "## When to use", ko: /^## 언제 사용하나/m },
  { en: "## Workflow", ko: /^## 워크플로/m },
  { en: "## Done when", ko: /^## 완료 조건/m },
];

const VALID_CATEGORIES = new Set([
  "recon", "vuln-analysis", "web-security", "crypto",
  "incident-response", "compliance", "code-security",
]);

let errors = 0;
let checked = 0;

const dirs = fs.readdirSync(REPO_ROOT, { withFileTypes: true })
  .filter(d => d.isDirectory() && !SKIP.has(d.name));

for (const dir of dirs) {
  const skillPath = path.join(REPO_ROOT, dir.name, "SKILL.md");
  if (!fs.existsSync(skillPath)) continue;

  checked++;
  const content = fs.readFileSync(skillPath, "utf-8");

  // 필수 섹션 검증 (영문 또는 한국어)
  for (const section of REQUIRED_SECTIONS) {
    const hasEn = content.includes(section.en);
    const hasKo = section.ko.test(content);
    if (!hasEn && !hasKo) {
      console.error(`FAIL: ${dir.name}/SKILL.md — missing section: ${section.en}`);
      errors++;
    }
  }

  // 카테고리 검증
  const catMatch = content.match(/category:\s*(.+)/);
  if (catMatch) {
    const cat = catMatch[1].trim();
    if (!VALID_CATEGORIES.has(cat)) {
      console.error(`FAIL: ${dir.name}/SKILL.md — invalid category: ${cat}`);
      errors++;
    }
  }
}

console.log(`\nChecked ${checked} skill(s), ${errors} failure(s).`);
process.exit(errors > 0 ? 1 : 0);
