import { defineConfig } from "blume";
import { node } from "blume/deploy";

export default defineConfig({
  title: "dialctl",
  description:
    "Local-first TRAI TCCCPR A2P voice compliance gate: a sub-5ms pre-dial policy engine, a SHA-256 hash-chained attestation ledger, and an offline drift scanner.",

  content: {
    root: "docs",
  },

  theme: {
    accent: "teal",
    mode: "system",
  },

  seo: {
    og: { enabled: true },
    sitemap: true,
    robots: true,
  },

  // A node server build rather than a static one: the deploy target is a
  // container that serves dist/ itself, and only the server can set the
  // security headers on every response. A static _headers file is ignored
  // there (verified against the live host).
  deployment: node({
    site: "https://dialctl-docs.antideploy.app",
  }),
});