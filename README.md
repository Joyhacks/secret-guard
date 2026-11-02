# Secret Guard

A GitHub Action that fails the build when an API key or server secret is about to ship to the browser.

AI builders make this mistake constantly. Lovable, Bolt and Cursor will happily write `VITE_OPENAI_API_KEY` or drop a Supabase `service_role` key into a client file, and the app works fine until someone opens DevTools. Secret Guard catches it on the pull request, with the exact line annotated.

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

That's the whole setup. No dependencies, no account, nothing leaves the runner.

## What it catches

| Rule | Example | Level |
|---|---|---|
| `public-secret-name` | `VITE_OPENAI_API_KEY`, `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`, `REACT_APP_STRIPE_SECRET_KEY` | error |
| `supabase-service-role` | A Supabase JWT whose payload says `role: service_role`. Decoded, not guessed, so the anon key never trips it | error |
| `server-env-in-client` | A Next.js `'use client'` file reading `process.env.STRIPE_SECRET_KEY` | error |
| Literal keys | Stripe live secret and restricted keys, Supabase `sb_secret_`, OpenAI, Anthropic, AWS, GitHub, Slack, SendGrid, private keys | error |
| `stripe-test-secret` | `sk_test_...` in source | warning |
| `committed-env-secret` | A committed `.env` with a value for a secret-shaped name like `STRIPE_SECRET_KEY` or `DATABASE_URL` | error |

Public prefixes it understands: `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_` and `PUBLIC_` (SvelteKit, Astro).

What it deliberately leaves alone:

- Values that are public by design: the Supabase anon or publishable key, Stripe publishable keys, Mapbox tokens, `VITE_SUPABASE_URL`.
- The `.env` Lovable commits, which holds only public values.
- `.env.example` and other template files.
- `node_modules`, build output (`.next`, `dist`, `build`) and Markdown.

Secrets are never printed in full. Logs show `sk_liv...x9`, not the key.

## Options

```yaml
- uses: Joyhacks/secret-guard@v1
  with:
    path: apps/web          # default: repo root
    allow: VITE_RECAPTCHA_SITE_SECRET   # comma-separated names to skip
    strict: true            # also fail on warnings
    env-files: auto         # auto | on | off
```

To silence one line, add `secret-guard-ignore` in a comment on that line or the line above:

```ts
// secret-guard-ignore: test fixture, not a real key
const key = 'sk_test_...';
```

## Run it locally

```bash
npx github:Joyhacks/secret-guard --path .
```

Locally, `.env` files are skipped (they're supposed to hold secrets and should be gitignored), except for the public-prefix check, since a `VITE_` secret in `.env.local` still ends up in your bundle.

## Found something? Here's the fix

1. **Rotate the key first.** If it was ever committed or deployed, assume it's out. Deleting the line doesn't un-leak it.
2. Move the call that needs the key server-side: a Next.js route handler or server action, a Supabase Edge Function, or a serverless function.
3. Drop the public prefix and set the variable only in your server environment.
4. For a Supabase `service_role` key, also check your tables have RLS on. That key exists to bypass RLS, which is why a leaked one is so bad.

## Limits

This is a fast pattern scanner for the leaks that actually happen in AI-built apps. It doesn't replace a full secret scanner over git history (Gitleaks, TruffleHog) or a security review. It also can't see keys that are fetched at runtime from somewhere else.

## Need a hand?

If Secret Guard flagged a leak in a live app and you'd rather have someone fix it properly (rotate keys, move calls server-side, lock down RLS), that's what I do. Find me at [adeolaforgehq.com](https://adeolaforgehq.com).

MIT licensed. Built by [Adeola Ilori](https://github.com/Joyhacks).
