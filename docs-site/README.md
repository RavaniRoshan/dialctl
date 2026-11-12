# dialctl docs

The documentation site for dialctl, built with [Blume](https://useblume.dev) and
deployed at <https://dialctl-docs.antideploy.app>.

The site is a standalone Astro app (ejected from the Blume runtime so it can set
security headers on every response). Content lives in `docs/` as MDX, grouped by
the [Diátaxis](https://diataxis.fr) framework: tutorial, how-to, reference,
explanation.

## Develop

```sh
npm install
npm run dev        # dev server with hot reload
npm run build      # production build into dist/
```

Requires Node.js 22.19+.

## Verify

```sh
npm run doctor     # diagnose config and content problems
npm run validate   # check internal, anchor, and asset links
```

## Structure

| Path | Purpose |
|------|---------|
| `docs/` | MDX content, four Diátaxis groups |
| `src/pages/` | Ejected Blume routes (docs pages, Markdown mirrors, search, OG images) |
| `src/middleware.ts` | Security headers on every response |
| `security-headers-plugin.mjs` | Stamps the emitted Node server entry so prerendered pages are covered too |
| `Procfile` | Start command for the hosting platform |
| `astro.config.mjs` | Standalone Astro config |

## Deploy

Deployed to Antideploy as a Node server build. The platform runs `npm install`
and `npm run build`, then starts `dist/server/entry.mjs` on `$PORT`.