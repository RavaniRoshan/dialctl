// Vite plugin: set security headers on every response from the Node server.
//
// The docs are prerendered to static HTML, and @astrojs/node serves those from
// its static handler before Astro middleware runs — so middleware alone cannot
// set headers on the pages. This plugin rewrites the emitted server entry so
// every request goes through a wrapper that stamps the headers on the response
// before its body is written, whether it came from the static layer or SSR.
//
// Both the exported `handler` and the `createServer(...)` call inside
// `startServer` build their handler through `createStandaloneHandler`, so
// renaming that factory and routing both call sites through the wrapper covers
// every served response.

const HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
};

const PRELUDE = `var __DIALCTL_HEADERS = ${JSON.stringify(HEADERS)};

function __dialctlStamp(res) {
  for (const __k of Object.keys(__DIALCTL_HEADERS)) {
    if (!res.headersSent && !res.getHeader(__k)) {
      res.setHeader(__k, __DIALCTL_HEADERS[__k]);
    }
  }
}

function __dialctlWrapHandler(__inner) {
  return function (req, res, next) {
    res.on("finish", function () { __dialctlStamp(res); });
    var __result = __inner.call(this, req, res, function (err) {
      __dialctlStamp(res);
      if (typeof next === "function") return next(err);
      return undefined;
    });
    if (__result && typeof __result.then === "function") {
      return __result.then(function (r) { __dialctlStamp(res); return r; });
    }
    __dialctlStamp(res);
    return __result;
  };
}

`;

export function dialctlSecurityHeaders() {
  return {
    name: "dialctl-security-headers",
    enforce: "post",
    generateBundle(_options, bundle) {
      const entry = Object.entries(bundle).find(
        ([name, chunk]) => name.endsWith("entry.mjs") && chunk.type === "chunk"
      )?.[1];
      if (!entry || entry.code.includes("__DIALCTL_HEADERS")) return;

      // Rename the factory, then route every call site through the wrapper by
      // matching the call's opening paren and inserting the wrapper around the
      // whole argument list (balanced by scanning to its closing paren).
      let patched = entry.code.replace(
        /function createStandaloneHandler\(/g,
        "function __dialctlCreateStandaloneHandler(",
      );

      const CALL = "createStandaloneHandler(app,";
      let out = "";
      let i = 0;
      while (i < patched.length) {
        const at = patched.indexOf(CALL, i);
        if (at === -1) {
          out += patched.slice(i);
          break;
        }
        out += patched.slice(i, at);
        // Find the paren that closes this call's argument list.
        const open = patched.indexOf("(", at);
        let depth = 0;
        let close = -1;
        for (let j = open; j < patched.length; j++) {
          const ch = patched[j];
          if (ch === "(") depth++;
          else if (ch === ")") {
            depth--;
            if (depth === 0) { close = j; break; }
          }
        }
        const args = patched.slice(open + 1, close);
        out += `__dialctlWrapHandler(__dialctlCreateStandaloneHandler(${args})`;
        i = close;
      }
      patched = out;


      patched = patched.replace(
        "options.port ?? 8080;",
        "3000;",
      );
      patched = patched.replace(
        "const host = process.env.HOST ?? hostOptions(options.host);",
        'const host = process.env.HOST || "0.0.0.0";',
      );

      entry.code = PRELUDE + patched;
    },
  };
}