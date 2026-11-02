# secret-guard

A GitHub Action that fails a build when an API key or server-side secret ends up somewhere it will ship to the browser.

```yaml
# .github/workflows/secret-guard.yml
name: Secret Guard
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Joyhacks/secret-guard@v1
```

Findings show up as annotations on the exact line in the pull request. It's one Node script with no dependencies, and it doesn't send anything anywhere.

## Why

Frontend frameworks put any variable with a public prefix (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` and so on) into the JavaScript bundle. AI code generators get this wrong all the time. They'll write `VITE_OPENAI_API_KEY` or pass a Supabase `service_role` key to `createClient` in a component, and everything works until someone opens DevTools. General secret scanners catch committed credentials, but not a variable whose name decides that it gets published.

## Rules

| Rule | Catches | Level |
|---|---|---|
| `public-secret-name` | A public-prefixed variable named like a secret: `VITE_OPENAI_API_KEY`, `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`, `REACT_APP_STRIPE_SECRET_KEY` | error |
| `supabase-service-role` | A Supabase JWT whose decoded payload has `role: service_role`. Anon keys are decoded too and ignored | error |
| `server-env-in-client` | A Next.js `'use client'` file reading a non-public `process.env` value | error |
| literal keys | Stripe live secret and restricted keys, Supabase `sb_secret_`, OpenAI, Anthropic, AWS, GitHub, Slack, SendGrid, PEM private keys | error |
| `stripe-test-secret` | `sk_test_` keys in source | warning |
| `committed-env-secret` | A committed `.env` file with a value for a secret-shaped name (`*_KEY`, `*_SECRET`, `DATABASE_URL`, ...). CI only | error |

Prefixes it treats as public: `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`, `PUBLIC_`.

Things that are public by design aren't flagged: Supabase anon and publishable keys, Stripe publishable keys, Mapbox and similar browser tokens, and a `.env` that only holds public-prefixed values (Lovable commits one of these). Template files like `.env.example` are skipped, as are `node_modules`, build output and Markdown.

Matched secrets are masked in the output (`sk_liv...x9`), so the scan doesn't leak them into CI logs.

## Options

```yaml
- uses: Joyhacks/secret-guard@v1
  with:
    path: apps/web               # default: repo root
    allow: VITE_PUBLIC_SECRET_A  # comma-separated names to skip
    strict: true                 # fail on warnings too
    env-files: auto              # auto (CI only), on, off
```

To skip a single line, put `secret-guard-ignore` in a comment on it or on the line above:

```ts
// secret-guard-ignore: fixture for tests
const key = 'sk_test_...';
```

## Running locally

```bash
npx github:Joyhacks/secret-guard --path .
```

Outside CI, the contents of `.env` files aren't checked, because local `.env` files are meant to hold secrets. The public-prefix rule still runs on them, since a `VITE_` secret in `.env.local` still ends up in the bundle.

## If it finds something

Rotate the key first. If it was committed or deployed, treat it as leaked: removing the line doesn't change that. Then move whatever needs the key into server code (a route handler, server action, Supabase Edge Function or serverless function) and drop the public prefix. For a leaked Supabase `service_role` key, also check that every table has RLS on, since that key bypasses it.

## Limitations

It's a pattern scanner aimed at the leaks that actually happen in frontend code. It doesn't scan git history (use Gitleaks or TruffleHog for that) and can't see secrets fetched at runtime.

## Development

```bash
node --test test/*.test.mjs
```

CI runs the tests on Node 18, 20 and 22, then runs the action itself against `test/fixtures/clean` (must pass) and `test/fixtures/leaky` (must fail).

## License

MIT. Written by [Adeola Ilori](https://github.com/Joyhacks).
