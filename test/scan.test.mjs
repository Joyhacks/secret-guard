import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanText, scanDir, main, mask } from '../src/scan.mjs';

const rules = (text, file = 'app.tsx', opts) => scanText(text, file, opts).map((f) => f.rule);
// Built at runtime so this file never contains a scannable secret itself.
const jwt = (payload) => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', Buffer.from(JSON.stringify(payload)).toString('base64url'), 'c2lnbmF0dXJlLXZhbHVl'].join('.');
const fake = (prefix, n = 40) => prefix + 'a1B2c3D4e5'.repeat(Math.ceil(n / 10)).slice(0, n);

test('public-prefixed secret names are errors in every framework', () => {
  for (const name of ['NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY', 'VITE_OPENAI_API_KEY', 'REACT_APP_STRIPE_SECRET_KEY',
    'EXPO_PUBLIC_RESEND_API_KEY', 'PUBLIC_DATABASE_URL', 'NUXT_PUBLIC_ANTHROPIC_KEY', 'VITE_SENTRY_AUTH_TOKEN']) {
    assert.deepEqual(rules(`const k = import.meta.env.${name};`), ['public-secret-name'], name);
  }
});

test('public values meant for the browser are not flagged', () => {
  for (const name of ['NEXT_PUBLIC_SUPABASE_ANON_KEY', 'VITE_SUPABASE_PUBLISHABLE_KEY', 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
    'VITE_SUPABASE_URL', 'NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN', 'NEXT_PUBLIC_POSTHOG_KEY', 'NEXT_PUBLIC_PRIVACY_URL']) {
    assert.deepEqual(rules(`process.env.${name}`), [], name);
  }
});

test('server-only names without a public prefix are fine in server code', () => {
  assert.deepEqual(rules('const k = process.env.SUPABASE_SERVICE_ROLE_KEY;', 'route.ts'), []);
});

test('use client files cannot read server env', () => {
  const src = "'use client';\nexport function A() { return process.env.STRIPE_SECRET_KEY + process.env.NODE_ENV + process.env.NEXT_PUBLIC_URL; }";
  assert.deepEqual(rules(src), ['server-env-in-client']);
  assert.deepEqual(rules('// comment\n"use client"\nprocess.env["DB_URL"]'), ['server-env-in-client']);
  assert.deepEqual(rules("process.env.STRIPE_SECRET_KEY // no directive"), []);
});

test('service_role JWT is caught by decoding it, anon JWT is not', () => {
  assert.deepEqual(rules(`createClient(url, "${jwt({ role: 'service_role', iss: 'supabase' })}")`), ['supabase-service-role']);
  assert.deepEqual(rules(`createClient(url, "${jwt({ role: 'anon', iss: 'supabase' })}")`), []);
  assert.deepEqual(rules('const t = "eyJnotreal.eyJnotreal.notreal1";'), []);
});

test('literal provider keys', () => {
  const cases = {
    'stripe-live-secret': fake('sk_live_'), 'stripe-test-secret': fake('sk_test_'), 'supabase-secret-key': fake('sb_secret_'),
    'openai-key': fake('sk-proj-', 48), 'anthropic-key': fake('sk-ant-api03-', 48), 'aws-access-key': 'AKIA' + 'ABCDEFGHIJKLMNOP',
    'github-token': 'ghp_' + 'a'.repeat(36), 'slack-token': fake('xoxb-', 30),
  };
  for (const [rule, key] of Object.entries(cases)) assert.deepEqual(rules(`const k = "${key}";`), [rule], rule);
  assert.deepEqual(rules('const k = "pk_live_abcdefghijklmnopqrstuvwx";'), [], 'publishable keys are fine');
  assert.deepEqual(rules('const PRIVATE = "-----BEGIN ' + 'PRIVATE KEY-----";', 'k.js'), ['private-key']);
});

test('findings never print the full secret', () => {
  const key = fake('sk_live_');
  const [f] = scanText(`"${key}"`, 'a.ts');
  assert.ok(!f.message.includes(key));
  assert.equal(mask('short'), '***');
});

test('ignore comment on the line or the line above', () => {
  const key = fake('sk_test_');
  assert.deepEqual(rules(`"${key}" // secret-guard-ignore`), []);
  assert.deepEqual(rules(`// secret-guard-ignore: test fixture\nconst k = "${key}";`), []);
});

test('allow list', () => {
  assert.deepEqual(rules('import.meta.env.VITE_RECAPTCHA_SECRET', 'a.ts', { allow: new Set(['VITE_RECAPTCHA_SECRET']) }), []);
});

test('env files: skipped locally except public-secret names', () => {
  const env = `SUPABASE_SERVICE_ROLE_KEY=${jwt({ role: 'service_role' })}\nVITE_OPENAI_API_KEY=x\n`;
  assert.deepEqual(rules(env, '.env.local', { envFiles: false }), ['public-secret-name']);
});

test('env files in CI: secret values flagged, Lovable-style public env is fine', () => {
  const lovable = 'VITE_SUPABASE_PROJECT_ID="abc"\nVITE_SUPABASE_PUBLISHABLE_KEY="eyJ..."\nVITE_SUPABASE_URL="https://abc.supabase.co"\n';
  assert.deepEqual(rules(lovable, '.env', { envFiles: true }), []);
  const bad = 'PORT=3000\nNEXTAUTH_URL=http://localhost:3000\nSTRIPE_SECRET_KEY=sk_x\nDATABASE_URL=\n# API_KEY=commented\n';
  assert.deepEqual(rules(bad, '.env', { envFiles: true }), ['committed-env-secret']);
  assert.deepEqual(rules('STRIPE_SECRET_KEY=sk_x', '.env.example', { envFiles: true }), []);
});

test('directory scan skips build output and node_modules', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sg-'));
  for (const d of ['src', 'node_modules/pkg', '.next/static', 'dist']) mkdirSync(join(dir, d), { recursive: true });
  const leak = `const k = import.meta.env.VITE_OPENAI_API_KEY;`;
  writeFileSync(join(dir, 'src/a.ts'), leak);
  writeFileSync(join(dir, 'node_modules/pkg/i.js'), leak);
  writeFileSync(join(dir, '.next/static/c.js'), leak);
  writeFileSync(join(dir, 'dist/b.js'), leak);
  writeFileSync(join(dir, 'README.md'), leak);
  const r = scanDir(dir);
  assert.equal(r.findings.length, 1);
  assert.match(r.findings[0].file, /src[\\/]a\.ts$/);
});

test('CLI exit codes and GitHub annotation format', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sg-'));
  writeFileSync(join(dir, 'ok.ts'), 'export const x = 1;');
  const out = [];
  assert.equal(main(['--path', dir, '--format', 'text'], (l) => out.push(l)), 0);
  writeFileSync(join(dir, 'bad.ts'), `const a = "${fake('sk_test_')}";`);
  assert.equal(main(['--path', dir], () => {}), 0, 'warnings alone pass');
  assert.equal(main(['--path', dir, '--strict'], () => {}), 1, 'strict fails on warnings');
  writeFileSync(join(dir, 'worse.ts'), 'import.meta.env.VITE_OPENAI_API_KEY');
  const gh = [];
  assert.equal(main(['--path', dir, '--format', 'github'], (l) => gh.push(l)), 1);
  assert.ok(gh.some((l) => /^::error file=.*worse\.ts,line=1,title=Secret Guard%3A public-secret-name::/.test(l)));
  assert.equal(main(['--bogus'], () => {}), 2);
  assert.equal(main(['--env-files', 'maybe'], () => {}), 2);
});
