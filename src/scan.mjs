#!/usr/bin/env node
/**
 * Secret Guard: catches secrets headed for the browser before they ship.
 *
 * Works on Next.js, Vite (Lovable, Bolt), Create React App, Expo, SvelteKit,
 * Astro, Nuxt and Gatsby projects. Zero dependencies.
 *
 * Usage:
 *   node scan.mjs [--path .] [--allow NAME,NAME] [--strict] [--env-files auto|on|off] [--format text|github]
 *
 * Exit codes: 0 clean, 1 findings at error level (or any finding with --strict), 2 bad usage.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, basename, extname } from 'node:path';

// ---------- rules ----------

// Prefixes that frameworks inline into the client bundle.
export const PUBLIC_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'REACT_APP_', 'EXPO_PUBLIC_', 'NUXT_PUBLIC_', 'GATSBY_', 'PUBLIC_'];

// A public variable with one of these names is almost always a mistake.
const SECRET_NAME = new RegExp(
  [
    'SERVICE_ROLE', 'SECRET', 'PRIVATE', 'PASSWORD', 'PASSWD', 'AUTH_TOKEN', 'ACCESS_TOKEN', 'REFRESH_TOKEN',
    '(OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|COHERE|REPLICATE|DEEPSEEK|PERPLEXITY|ELEVENLABS|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO|BREVO|AIRTABLE|NOTION|HUBSPOT|SHOPIFY_ADMIN)_?(API_?)?KEY',
    'DATABASE_URL', 'DB_PASSWORD', 'POSTGRES_URL',
  ].join('|'),
);

// Tokens that providers issue specifically for browsers.
const KNOWN_PUBLIC = /(MAPBOX|CESIUM|CONTENTFUL|STORYBLOK|DATOCMS|ALGOLIA_SEARCH)/;

// High-confidence literal secrets. Each pattern is specific enough to avoid
// flagging ordinary identifiers.
const LITERALS = [
  { id: 'stripe-live-secret', level: 'error', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g, what: 'Stripe live secret key' },
  { id: 'stripe-test-secret', level: 'warning', re: /\bsk_test_[0-9a-zA-Z]{20,}\b/g, what: 'Stripe test secret key' },
  { id: 'supabase-secret-key', level: 'error', re: /\bsb_secret_[0-9a-zA-Z_-]{20,}\b/g, what: 'Supabase secret API key' },
  { id: 'openai-key', level: 'error', re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g, what: 'OpenAI API key' },
  { id: 'anthropic-key', level: 'error', re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g, what: 'Anthropic API key' },
  { id: 'aws-access-key', level: 'error', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, what: 'AWS access key ID' },
  { id: 'github-token', level: 'error', re: /\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, what: 'GitHub token' },
  { id: 'slack-token', level: 'error', re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g, what: 'Slack token' },
  { id: 'sendgrid-key', level: 'error', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, what: 'SendGrid API key' },
  { id: 'private-key', level: 'error', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, what: 'private key' },
];

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro']);
const SKIP_DIRS = new Set(['node_modules', '.git', '.next', '.nuxt', '.svelte-kit', '.output', '.vercel', '.netlify', 'dist', 'build', 'out', 'coverage', 'vendor', '.turbo', '.cache']);
const ENV_FILE = /^\.env(\..+)?$/;
const ENV_TEMPLATE = /\.(example|sample|template|dist|defaults)$/;
const IGNORE_MARK = 'secret-guard-ignore';

// ---------- helpers ----------

export function mask(s) {
  return s.length <= 10 ? '***' : `${s.slice(0, 6)}...${s.slice(-2)}`;
}

function jwtRole(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return payload && typeof payload.role === 'string' ? payload.role : null;
  } catch {
    return null;
  }
}

const isPublic = (name) => PUBLIC_PREFIXES.some((p) => name.startsWith(p));
const lineOf = (text, index) => text.slice(0, index).split('\n').length;

function walk(dir, root, out) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, root, out);
    else if (st.size <= 2_000_000 && (CODE_EXT.has(extname(name)) || ENV_FILE.test(name))) out.push(full);
  }
  return out;
}

// ---------- scanning ----------

/**
 * Scan one file's text. Pure function, exported for tests.
 * @returns {Array<{level:'error'|'warning', rule:string, line:number, message:string}>}
 */
export function scanText(text, fileName, { allow = new Set(), envFiles = false } = {}) {
  const findings = [];
  const lines = text.split('\n');
  const ignored = (line) => (lines[line - 1] || '').includes(IGNORE_MARK) || (lines[line - 2] || '').includes(IGNORE_MARK);
  const push = (level, rule, index, message) => {
    const line = lineOf(text, index);
    if (!ignored(line)) findings.push({ level, rule, line, message });
  };
  const base = basename(fileName);
  const isEnv = ENV_FILE.test(base);
  if (isEnv && ENV_TEMPLATE.test(base)) return findings;

  // Public-prefixed variables named like secrets, in code or env files.
  const nameRe = /\b([A-Z][A-Z0-9_]{3,})\b/g;
  const seen = new Set();
  for (const m of text.matchAll(nameRe)) {
    const name = m[1];
    if (!isPublic(name) || allow.has(name) || seen.has(name)) continue;
    const bare = PUBLIC_PREFIXES.reduce((n, p) => (n.startsWith(p) ? n.slice(p.length) : n), name);
    if (!SECRET_NAME.test(bare) || KNOWN_PUBLIC.test(bare)) continue;
    seen.add(name);
    push('error', 'public-secret-name', m.index,
      `${name} looks like a secret but its prefix ships it to every visitor's browser. Move it server-side (API route, server action or edge function) and drop the public prefix.`);
  }

  if (isEnv) {
    // Locally, .env files are supposed to hold secrets (they're gitignored).
    // Only judge their contents in CI, where the checkout is exactly what's in git.
    if (!envFiles) return findings;
    // Committed env file holding server-side values. Public-prefixed values
    //    (VITE_SUPABASE_URL, the anon key) ship to the browser anyway, so a file
    //    with only those, like the one Lovable commits, is fine.
    lines.forEach((l, i) => {
      const m = l.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
      if (!m || /^\s*#/.test(l) || allow.has(m[1]) || isPublic(m[1])) return;
      if (!/(KEY|TOKEN|SECRET|PASSWORD|PASSWD|DSN|CREDENTIAL|PRIVATE|DATABASE_URL|CONNECTION_STRING|_URI$)/.test(m[1])) return;
      const value = m[2].trim().replace(/^['"]|['"]$/g, '');
      if (!value) return;
      if (!ignored(i + 1)) {
        findings.push({ level: 'error', rule: 'committed-env-secret', line: i + 1,
          message: `${m[1]} has a value in committed file ${base}. Anyone with repo access has it. Remove the file from git, add it to .gitignore and rotate this value.` });
      }
    });
  } else {
    // Server-only env read from a Next.js client component.
    const head = text.slice(0, 400);
    if (/^\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/\s*)*\s*['"]use client['"]/.test(head)) {
      for (const m of text.matchAll(/process\.env\.([A-Z0-9_]+)|process\.env\[['"]([A-Z0-9_]+)['"]\]/g)) {
        const name = m[1] || m[2];
        if (name === 'NODE_ENV' || isPublic(name) || allow.has(name)) continue;
        push('error', 'server-env-in-client', m.index,
          `'use client' file reads process.env.${name}. Next.js only inlines NEXT_PUBLIC_ variables, so this is undefined in the browser, and renaming it to fix that would leak it. Read it on the server and pass down only what the UI needs.`);
      }
    }
  }

  for (const rule of LITERALS) {
    for (const m of text.matchAll(rule.re)) {
      push(rule.level, rule.id, m.index, `Hardcoded ${rule.what} (${mask(m[0])}). Remove it, rotate it, and load it from a server-side environment variable.`);
    }
  }
  for (const m of text.matchAll(JWT)) {
    const role = jwtRole(m[0]);
    if (role === 'service_role') {
      push('error', 'supabase-service-role', m.index,
        `Supabase service_role key (${mask(m[0])}). It bypasses every RLS policy. Rotate it in the Supabase dashboard now and use it only in server code.`);
    }
  }
  return findings;
}

export function scanDir(root, opts = {}) {
  const files = walk(root, root, []);
  const results = [];
  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    for (const f of scanText(text, file, opts)) results.push({ ...f, file: relative(process.cwd(), file) || file });
  }
  return { files: files.length, findings: results };
}

// ---------- CLI ----------

function parseArgs(argv) {
  const a = { path: '.', allow: '', strict: false, envFiles: 'auto', format: process.env.GITHUB_ACTIONS ? 'github' : 'text' };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${k} needs a value`);
      return argv[++i];
    };
    if (k === '--path') a.path = next();
    else if (k === '--allow') a.allow = next();
    else if (k === '--strict') a.strict = true;
    else if (k === '--env-files') a.envFiles = next();
    else if (k === '--format') a.format = next();
    else if (k === '--help' || k === '-h') a.help = true;
    else throw new Error(`Unknown option ${k}`);
  }
  if (!['auto', 'on', 'off'].includes(a.envFiles)) throw new Error('--env-files must be auto, on or off');
  if (!['text', 'github'].includes(a.format)) throw new Error('--format must be text or github');
  return a;
}

const esc = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s) => esc(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

export function main(argv = process.argv.slice(2), log = console.log) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    log(`secret-guard: ${e.message}`);
    return 2;
  }
  if (args.help) {
    log('Usage: secret-guard [--path .] [--allow NAME,NAME] [--strict] [--env-files auto|on|off] [--format text|github]');
    return 0;
  }
  const allow = new Set(args.allow.split(',').map((s) => s.trim()).filter(Boolean));
  const envFiles = args.envFiles === 'on' || (args.envFiles === 'auto' && !!process.env.CI);
  const { files, findings } = scanDir(args.path, { allow, envFiles });

  for (const f of findings) {
    if (args.format === 'github') {
      log(`::${f.level} file=${escProp(f.file)},line=${f.line},title=${escProp('Secret Guard: ' + f.rule)}::${esc(f.message)}`);
    } else {
      log(`${f.level === 'error' ? 'ERROR' : 'WARN '} ${f.file}:${f.line}  [${f.rule}]\n      ${f.message}`);
    }
  }
  const errors = findings.filter((f) => f.level === 'error').length;
  const warnings = findings.length - errors;
  log(`\nSecret Guard scanned ${files} files: ${errors} error(s), ${warnings} warning(s).`);
  return errors > 0 || (args.strict && warnings > 0) ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('scan.mjs')) {
  process.exitCode = main();
}
