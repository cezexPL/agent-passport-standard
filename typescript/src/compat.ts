import { readFileSync, readdirSync, mkdirSync, writeFileSync } from 'fs';
import { join, basename } from 'path';
import type { Skill, AgentsMD } from './types.js';

export function importAgentSkill(skillDir: string): Skill {
  const content = readFileSync(join(skillDir, 'SKILL.md'), 'utf-8');
  const name = basename(skillDir);
  const description = extractFirstLine(content);
  const capabilities = inferCapabilities(content);

  return {
    name,
    version: '1.0.0',
    description,
    capabilities,
    source: `agent-skills://${name}`,
    hash: '',
  };
}

export function exportAgentSkill(skill: Skill, outputDir: string): void {
  const skillDir = join(outputDir, skill.name);
  mkdirSync(skillDir, { recursive: true });

  let md = `# ${skill.name}\n\n${skill.description}\n\nVersion: ${skill.version}\n\n## Capabilities\n\n`;
  for (const cap of skill.capabilities) {
    md += `- ${cap}\n`;
  }
  writeFileSync(join(skillDir, 'SKILL.md'), md);
  writeFileSync(join(skillDir, 'metadata.json'), JSON.stringify(skill, null, 2));
}

export function loadAgentsMd(repoPath: string): AgentsMD {
  const content = readFileSync(join(repoPath, 'AGENTS.md'), 'utf-8');
  const result: AgentsMD = { raw: content, instructions: [], constraints: [], tools: [] };

  let section = '';
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    const lower = trimmed.toLowerCase();

    if (trimmed.startsWith('#')) {
      if (lower.includes('instruction') || lower.includes('rules')) section = 'instructions';
      else if (lower.includes('constraint') || lower.includes('restriction')) section = 'constraints';
      else if (lower.includes('tool') || lower.includes('mcp')) section = 'tools';
      else section = '';
      continue;
    }

    if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
      const item = trimmed.replace(/^[-*]\s+/, '');
      if (section === 'instructions') result.instructions.push(item);
      else if (section === 'constraints') result.constraints.push(item);
      else if (section === 'tools') result.tools.push(item);
    }
  }

  return result;
}

function extractFirstLine(content: string): string {
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) return trimmed;
  }
  return '';
}

function inferCapabilities(content: string): string[] {
  const lower = content.toLowerCase();
  const caps: string[] = [];
  if (lower.includes('code') || lower.includes('develop')) caps.push('code_write');
  if (lower.includes('test')) caps.push('test_run');
  if (lower.includes('debug')) caps.push('debug');
  if (lower.includes('build')) caps.push('build');
  if (lower.includes('review') || lower.includes('audit')) caps.push('code_review');
  if (lower.includes('data') || lower.includes('analyz')) caps.push('data_read');
  if (caps.length === 0) caps.push('general');
  return caps;
}
