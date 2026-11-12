import { defineConfig } from "blume";

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

  deployment: {
    site: "https://dialctl-docs.antideploy.app",
  },
});