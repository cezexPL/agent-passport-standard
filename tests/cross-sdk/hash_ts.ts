import { readFileSync } from 'fs';
import { createHash } from 'crypto';

function canonicalize(obj: any): string {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

// keccak256 via Node.js (needs node 20+ with shake support — fallback to sha3-256 not keccak)
// For true keccak256 we need a library. Use js-sha3.
import { keccak256 } from 'js-sha3';

const data = JSON.parse(readFileSync(process.argv[2], 'utf-8'));
const canonical = canonicalize(data);
const hash = '0x' + keccak256(canonical);
console.log(hash);
