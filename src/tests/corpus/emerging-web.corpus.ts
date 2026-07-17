import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "WEB_PROXY_MIDDLEWARE_HEADER_UNSTRIPPED",
    check: "emerging-web",
    positive: {
      file: "nginx/default.conf",
      content: `server {\n  listen 80;\n  server_name app.example.com;\n\n  location / {\n    proxy_pass http://app_upstream;\n    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n  }\n}\n`
    },
    negative: {
      file: "nginx/default.conf",
      content: `server {\n  listen 80;\n  server_name app.example.com;\n\n  location / {\n    proxy_pass http://app_upstream;\n    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header x-middleware-subrequest "";\n  }\n}\n`
    },
    note: "Negative adds the exact stripping directive the rule's requiredActions prescribe (`proxy_set_header x-middleware-subrequest \"\";`); the proxy still forwards traffic (proxy_pass present) so it isn't just an unrelated config."
  },
  {
    ruleId: "WEB_RSC_FLIGHT_DESERIALIZATION_RCE",
    check: "emerging-web",
    positive: {
      file: "package.json",
      content: `{\n  "name": "app",\n  "dependencies": {\n    "react": "19.1.0",\n    "react-dom": "19.1.0"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "app",\n  "dependencies": {\n    "react": "19.2.1",\n    "react-dom": "19.2.1"\n  }\n}\n`
    },
    note: "Both pin a concrete (non-range) react version so resolveConcreteVersion succeeds either way; the negative is above the 19.0.0-19.2.0 affected window (React2Shell), not an unresolvable range that would merely downgrade the finding to a review."
  },
  {
    ruleId: "WEB_DJANGO_ORM_CONNECTOR_SQLI",
    check: "emerging-web",
    positive: {
      file: "app/views.py",
      content: `from django.shortcuts import render\nfrom .models import Product\n\n\ndef search(request):\n    results = Product.objects.filter(**request.GET.dict())\n    return render(request, "results.html", {"results": results})\n`
    },
    negative: {
      file: "app/views.py",
      content: `from django.shortcuts import render\nfrom .models import Product\n\nALLOWED_FILTERS = {"category", "in_stock"}\n\n\ndef search(request):\n    category = request.GET.get("category")\n    in_stock = request.GET.get("in_stock")\n    results = Product.objects.filter(category=category, in_stock=in_stock)\n    return render(request, "results.html", {"results": results})\n`
    },
    note: "Negative still reads from request.GET (so it isn't just deleting the user-input signal) but never unpacks a dict into filter/exclude/get/Q with `**`; kwargs are named explicitly per field, matching the rule's allowlist remediation, so the `.filter(**` / `Q(**` source pattern never appears."
  },
  {
    ruleId: "WEB_KESTREL_CHUNKED_SMUGGLING",
    check: "emerging-web",
    positive: {
      file: "src/Program.cs",
      content: `var builder = WebApplication.CreateBuilder(args);\nAppContext.SetSwitch("Microsoft.AspNetCore.Server.Kestrel.InsecureChunkedParsing", true);\nvar app = builder.Build();\napp.Run();\n`
    },
    negative: {
      file: "src/Program.cs",
      content: `var builder = WebApplication.CreateBuilder(args);\n// Keep the legacy chunked-parsing compatibility switch disabled now that the\n// runtime carries the CVE-2025-55315 fix.\nAppContext.SetSwitch("Microsoft.AspNetCore.Server.Kestrel.InsecureChunkedParsing", false);\nvar app = builder.Build();\napp.Run();\n`
    },
    note: "Negative keeps the same SetSwitch call site (not a deletion) but flips the value to false, exactly the rule's 'set it to false' remediation; the compat-flag regex requires a trailing literal `true` so it no longer matches."
  },
  {
    ruleId: "WEB_JWT_JKU_X5U_SSRF",
    check: "emerging-web",
    positive: {
      file: "src/auth/verifyJwt.ts",
      content: `import fetch from "node-fetch";\nimport { decodeJwtHeader } from "./decode.js";\n\nexport async function fetchSigningKey(token: string) {\n  const decoded = decodeJwtHeader(token);\n  const res = await fetch(decoded.header.jku);\n  return res.json();\n}\n`
    },
    negative: {
      file: "src/auth/verifyJwt.ts",
      content: `import fetch from "node-fetch";\nimport { decodeJwtHeader } from "./decode.js";\n\nconst TRUSTED_JWKS_ENDPOINT = process.env.JWKS_URL as string;\n\nexport async function fetchSigningKey(token: string) {\n  const decoded = decodeJwtHeader(token);\n  // Ignore any jku/x5u the token itself claims; always fetch from our own\n  // server-side-pinned JWKS endpoint instead.\n  const res = await fetch(TRUSTED_JWKS_ENDPOINT);\n  return res.json();\n}\n`
    },
    note: "Negative still decodes the header (so the shape of the code is preserved) but the fetch call never references jku/x5u anywhere in its argument list, matching the rule's own advice to pin the key endpoint in server config and ignore header-supplied URLs."
  },
  {
    ruleId: "WEB_PATH_TO_REGEXP_REDOS",
    check: "emerging-web",
    positive: {
      file: "package-lock.json",
      content: `{\n  "name": "app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": {\n      "dependencies": {\n        "express": "^4.19.2"\n      }\n    },\n    "node_modules/path-to-regexp": {\n      "version": "0.1.7",\n      "resolved": "https://registry.npmjs.org/path-to-regexp/-/path-to-regexp-0.1.7.tgz",\n      "integrity": "sha512-placeholder"\n    }\n  }\n}\n`
    },
    negative: {
      file: "package-lock.json",
      content: `{\n  "name": "app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": {\n      "dependencies": {\n        "express": "^4.19.2"\n      }\n    },\n    "node_modules/path-to-regexp": {\n      "version": "8.2.0",\n      "resolved": "https://registry.npmjs.org/path-to-regexp/-/path-to-regexp-8.2.0.tgz",\n      "integrity": "sha512-placeholder"\n    }\n  }\n}\n`
    },
    note: "Same lockfile shape and same major-line resolution path; the negative's resolved version (8.2.0) is above the 8.0.0 patched threshold for its major, so isBelowMajorAwareThresholds returns false instead of relying on an unresolvable/missing version."
  }
];
