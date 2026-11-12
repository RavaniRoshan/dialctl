// Written by `blume eject`. This is your Astro config now: edit it freely.
import { availableParallelism } from "node:os";
import { fileURLToPath } from "node:url";
import { defineConfig, fontProviders } from "astro/config";
import mdx from "@astrojs/mdx";
import tailwindcss from "@tailwindcss/vite";
import { blumeMarkdownProcessor, blumeMdxProcessor, blumeShikiTransformers, blumeTwoslashTransformer } from "blume/markdown";
import { blumeIntegration, includeHmrPlugin, mdxSourceErrorsPlugin, prerenderDepsPlugin } from "blume/astro";
import adapter from "@astrojs/node";
import { dialctlSecurityHeaders } from "./security-headers-plugin.mjs";

export default defineConfig({
  root: ".",
  srcDir: "./src",
  outDir: "./dist",
  publicDir: "./public",
  output: "server",
  adapter: adapter({"mode":"standalone"}),
  site: "https://dialctl-docs.antideploy.app",
  fonts: [{ provider: fontProviders.google(), name: "Inter", cssVariable: "--blume-ff-inter", weights: ["400 700"], subsets: ["latin"], fallbacks: ["ui-sans-serif","system-ui","sans-serif"] }, { provider: fontProviders.google(), name: "IBM Plex Mono", cssVariable: "--blume-ff-ibm-plex-mono", weights: [400,500,600], subsets: ["latin"], fallbacks: ["ui-monospace","SF Mono","Menlo","monospace"] }],
  integrations: [mdx({ processor: blumeMdxProcessor({ ...{"basePath":"","codeThemes":{"dark":"github-dark","light":"github-light"},"contentRoot":"docs","deployBase":"","externalLinks":false,"headingAnchors":true,"variables":{}}, dataFile: fileURLToPath(new URL("./src/generated/data.json", import.meta.url)) }) }), blumeIntegration({"pages":[],"poweredBy":true,"buildArtifactsRoot":".","contentRoutes":["/","/explanation/scope","/explanation/why-a-local-gate","/how-to/run-pre-dial-gate","/how-to/verify-the-ledger","/reference/cli-and-http","/reference/rules","/tutorial/first-blocked-call"],"homeLinkHeader":"</openapi.json>; rel=\"service-desc\"; type=\"application/json\", </index.md>; rel=\"alternate\"; type=\"text/markdown\""})],
  markdown: {
    processor: blumeMarkdownProcessor({ ...{"basePath":"","codeThemes":{"dark":"github-dark","light":"github-light"},"contentRoot":"docs","deployBase":"","externalLinks":false,"headingAnchors":true,"variables":{}}, dataFile: fileURLToPath(new URL("./src/generated/data.json", import.meta.url)) }),
    shikiConfig: {
      themes: {
        light: "github-light",
        dark: "github-dark",
      },
      defaultColor: false,
      transformers: [blumeTwoslashTransformer(), ...blumeShikiTransformers({"icons":true})],
    },
  },
  devToolbar: { enabled: false },
  // One canonical URL per page: canonicals, the sitemap, and hreflang all use
  // the slashless form, so the slashed spelling is not a second address. Astro
  // applies this itself — an on-demand route redirects, and the integration
  // has the dev server redirect too, ahead of Astro's own 404 — and the Vercel
  // adapter turns it into the platform's 308 route, so the Build Output config
  // needs no hand-spliced redirect (see deploy/vercel-negotiation.ts). Static hosts
  // serve the `index.html` directory layout as they always did.
  trailingSlash: "never",
  // The layouts render Astro's <ClientRouter />, and its in-place swaps read
  // from the prefetch cache — fetching every link on hover/viewport hides the
  // request latency behind the user's intent, so most navigations swap
  // instantly.
  prefetch: { prefetchAll: true },
  // Prerender several pages at once. Rendering is single-threaded, but a
  // page's OG card renders on a native thread and its HTML is written
  // asynchronously, so the main thread would otherwise idle behind each
  // page's off-thread work. Capped at 8: the gain flattens there and beyond it
  // the overlap only adds memory.
  build: { concurrency: Math.min(8, availableParallelism()) },
  vite: {
    plugins: [tailwindcss(), includeHmrPlugin(fileURLToPath(new URL("./src/generated/includes.json", import.meta.url))), mdxSourceErrorsPlugin(), prerenderDepsPlugin(), dialctlSecurityHeaders()],
    build: {
      rolldownOptions: {
        onLog(level, log, handler) {
          if (log.code === "MODULE_LEVEL_DIRECTIVE" && String(log.message).includes("use astro:head-inject")) {
            return;
          }
          handler(level, log);
        },
      },
    },
    // Everything hydration can reach must be part of the dev dep optimizer's
    // FIRST run. The Vite root is the generated runtime, so user pages,
    // islands, and aliased components live outside it and are only crawled
    // when first requested — and `react/compiler-runtime` is injected by the
    // React Compiler, so no source scan can ever see it. A dependency discovered after
    // hydration begins triggers a mid-session re-optimization whose new
    // generation imports React through new `?v=` URLs; the browser then
    // evaluates a second React copy and every island tears down with
    // "Invalid hook call" (#157). `entries` points the startup scanner at
    // the user's files (the scanner follows their imports, so their deps land
    // in the initial optimization); the compiler runtime rides the include
    // list because only the transform pipeline knows it exists.
    //
    // The mermaid/epub includes fix CJS interop instead: both lazy client-side
    // imports land on CJS/UMD files (mermaid statically imports dayjs as CJS,
    // epub-gen-memory's browser bundle is a browserified UMD) that break when
    // served as raw ESM — mermaid throws on load and the EPUB export throws
    // `epub is not a function`. They resolve through the `blume` package
    // (they aren't direct deps of the generated project), so the nested
    // `blume > x` form is required, and epub-gen-memory must name the
    // `/bundle` subpath that is actually imported: optimizing the package
    // root leaves that entry out. Production (Rollup) already handles the
    // interop, so all of this only affects dev.
    //
    // The search adapter's client library rides the list for the same reason
    // as the compiler runtime: the search dialog lazy-imports it on first
    // open, and discovering it then re-optimizes and reloads the page.
    optimizeDeps: {
      entries: ["./islands/**/*.{jsx,svelte,tsx,vue}"],
      include: ["blume > @orama/orama"],
    },
    // Blume's render-time deps are forced external on both build environments so
    // native bindings resolve at runtime and isolated linkers don't bundle
    // symlinked store copies (which would surface their children as unresolvable
    // imports). See RENDER_EXTERNAL_DEPS / prerenderDepsPlugin.
    //
    // The SSR externals go through the legacy `ssr.external` key rather than
    // `environments.ssr`: defining a user-owned `environments.ssr` block
    // collides with the internal environment Astro 7 builds the server under and
    // detaches the adapter's server entrypoint from the rolldown input, so the
    // SSR entry is emitted as `index.mjs` instead of the `entry.mjs` the
    // Vercel adapter's `astro:build:done` hook then fails to find. `prerender`
    // is Astro-only and has no legacy equivalent, so it stays under `environments`.
    ssr: { external: ["@astrojs/markdown-satteri","@pierre/diffs","@shikijs/transformers","@takumi-rs/core","@takumi-rs/helpers","@takumi-rs/wasm","github-slugger","katex","shiki","simple-icons","takumi-js","takumi-js/helpers","zod"] },
    environments: {
      prerender: { resolve: { external: ["@astrojs/markdown-satteri","@pierre/diffs","@shikijs/transformers","@takumi-rs/core","@takumi-rs/helpers","@takumi-rs/wasm","github-slugger","katex","shiki","simple-icons","takumi-js","takumi-js/helpers","zod"] } },
    },
    resolve: {
      alias: {
        "blume:ask": fileURLToPath(new URL("./src/generated/Ask.astro", import.meta.url)),
        "blume:consent-client": fileURLToPath(new URL("./src/generated/consent-client.ts", import.meta.url)),
        "blume:examples": fileURLToPath(new URL("./src/generated/examples.ts", import.meta.url)),
        "blume:examples-theme": fileURLToPath(new URL("./src/generated/examples.css", import.meta.url)),
        "blume:features": fileURLToPath(new URL("./src/generated/features.ts", import.meta.url)),
        "blume:search-client": fileURLToPath(new URL("./src/generated/search-client.ts", import.meta.url)),
        "blume:theme": fileURLToPath(new URL("./src/generated/app.css", import.meta.url)),
        "blume:ask-data": fileURLToPath(new URL("./src/generated/ask-data.json", import.meta.url)),
        "blume:content-assets": fileURLToPath(new URL("./src/generated/content-assets.json", import.meta.url)),
        "blume:data": fileURLToPath(new URL("./src/generated/data.json", import.meta.url)),
        "blume:mcp-data": fileURLToPath(new URL("./src/generated/mcp-data.json", import.meta.url)),
        "blume:openapi": fileURLToPath(new URL("./src/generated/openapi.json", import.meta.url)),
        "blume:raw-markdown": fileURLToPath(new URL("./src/generated/raw-markdown.json", import.meta.url)),
        "blume:rss": fileURLToPath(new URL("./src/generated/rss.json", import.meta.url)),
        "blume:search-index": fileURLToPath(new URL("./src/generated/search.json", import.meta.url)),
      },
    },
    server: {
      fs: {
        allow: ["."],
      },
    },
  },
});
