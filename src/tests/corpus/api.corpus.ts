import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "API_VALIDATION_MISSING",
    check: "api",
    positive: {
      file: "src/routes/users.ts",
      content: `import { Router } from "express";

const router = Router();

router.post("/users", (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  // No schema validation here - trusts whatever shape the client sends.
  db.users.insertOne({ name, email });
  res.status(201).send({ ok: true });
});

export default router;
`
    },
    negative: {
      file: "src/routes/users.ts",
      content: `import { Router } from "express";
import { z } from "zod";

const router = Router();

const CreateUserSchema = z.object({
  name: z.string().min(1).max(120),
  email: z.string().email()
});

router.post("/users", (req, res) => {
  const parsed = CreateUserSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  db.users.insertOne(parsed.data);
  res.status(201).send({ ok: true });
});

export default router;
`
    },
    note: "Rule fires when a repo-wide search for zod|valibot|yup|joi finds zero hits. The negative imports and uses zod to define and enforce a schema before touching req.body, which is the exact remediation the rule's requiredActions describe."
  },
  {
    ruleId: "CSRF_MAY_BE_MISSING",
    check: "api",
    positive: {
      file: "src/routes/account.ts",
      content: `import { Router } from "express";

const router = Router();

router.post("/account/email", (req, res) => {
  updateEmail(req.session.userId, req.body.email);
  res.status(200).send({ ok: true });
});

export default router;
`
    },
    negative: {
      file: "src/routes/account.ts",
      content: `import { Router } from "express";
import csrf from "csurf";

const router = Router();
const csrfProtection = csrf({ cookie: { sameSite: "strict" } });

router.post("/account/email", csrfProtection, (req, res) => {
  updateEmail(req.session.userId, req.body.email);
  res.status(200).send({ ok: true });
});

export default router;
`
    },
    note: "Rule fires when a repo-wide search for csrf|xsrf finds zero hits. The negative wires a csrf-protection middleware (variable name csrfProtection contains the literal substring 'csrf') into the state-changing route, matching requiredActions."
  },
  {
    ruleId: "IDOR_RISK_REVIEW",
    check: "api",
    positive: {
      file: "src/routes/orders.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/orders/:id", (req, res) => {
  const order = db.orders.findById(req.params.id);
  res.json(order);
});

export default router;
`
    },
    negative: {
      file: "src/routes/orders.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/orders/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const order = await db.orders.findById(id);
  if (!order || order.ownerId !== req.session.accountId) {
    return res.status(404).json({ error: "Not found" });
  }
  res.json(order);
});

export default router;
`
    },
    note: "The rule is a broad review flag keyed only on the literal substrings 'req.query.', 'params.', or 'userId =' — it has no way to detect whether an authz check exists. The negative enforces real ownership authorization (order.ownerId !== req.session.accountId) but reaches the id via destructuring (`const { id } = req.params;`, which never produces the substring 'params.') and names the session field accountId rather than userId, so it exercises the identical fetch-by-id shape without the three literal patterns the regex is keyed on. This is an idiomatic Express pattern, not a cosmetic rename to dodge detection."
  },
  {
    ruleId: "API_TENANT_ID_FROM_INPUT",
    check: "api",
    positive: {
      file: "src/routes/reports.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/reports", (req, res) => {
  const tenantId = req.query.tenantId;
  return res.json(db.reports.findMany({ where: { tenantId } }));
});

export default router;
`
    },
    negative: {
      file: "src/routes/reports.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/reports", requireAuth, (req, res) => {
  const tenantId = req.session.tenantId;
  return res.json(db.reports.findMany({ where: { tenantId } }));
});

export default router;
`
    },
    note: "Positive matches tenantId\\s*[:=]\\s*req\\.(query|params|body). Negative sources tenantId from req.session (not query/params/body), which the regex explicitly does not match, and is the exact fix requiredActions describes."
  },
  {
    ruleId: "API_MISSING_TENANT_SCOPE",
    check: "api",
    positive: {
      file: "src/routes/invoices.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/invoices", async (req, res) => {
  const invoices = await db.invoices.findMany();
  res.json(invoices);
});

export default router;
`
    },
    negative: {
      file: "src/routes/invoices.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/invoices", requireAuth, async (req, res) => {
  const invoices = await db.invoices.findMany({ where: { tenantId: req.session.tenantId } });
  res.json(invoices);
});

export default router;
`
    },
    note: "Rule fires when an ORM query call (findMany/findAll/find(/query(/select() is present but no tenantId|tenant_id|organizationId|orgId appears anywhere in the repo. Negative adds an explicit tenantId filter sourced from the session, which both fixes the leak and suppresses the finding by introducing the tenant-scope keyword the rule searches for."
  },
  {
    ruleId: "API_CACHE_NOT_TENANT_SCOPED",
    check: "api",
    positive: {
      file: "src/services/profileCache.ts",
      content: `async function getUserProfile(id) {
  const cached = cache.get("user:profile");
  if (cached) return cached;
  const profile = await db.users.findById(id);
  cache.set("user:profile", profile);
  return profile;
}

module.exports = { getUserProfile };
`
    },
    negative: {
      file: "src/services/profileCache.ts",
      content: `async function getTenantUserProfile(tenantId, userId) {
  const cached = cache.get("tenant:" + tenantId + ":user:" + userId);
  if (cached) return cached;
  const profile = await db.users.findById(userId);
  cache.set("tenant:" + tenantId + ":user:" + userId, profile);
  return profile;
}

module.exports = { getTenantUserProfile };
`
    },
    note: "Rule requires a cache.get(\"...\")/redis.get( call (quoted-literal argument, per the regex) with zero occurrences of tenantId|tenant:|orgId|userId: anywhere in the repo. The negative keeps cache.get called with a quoted string literal (so it still counts as a cache operation) but prefixes the key with the literal text 'tenant:', which is exactly requiredActions' recommended key shape (tenant:{id}:resource:{id})."
  },
  {
    ruleId: "API_FILE_PATH_FROM_INPUT",
    check: "api",
    positive: {
      file: "src/routes/files.ts",
      content: `import fs from "fs";
import { Router } from "express";

const router = Router();

router.get("/files", (req, res) => {
  fs.readFile(req.query.path, (err, data) => {
    if (err) return res.status(404).end();
    res.send(data);
  });
});

export default router;
`
    },
    negative: {
      file: "src/routes/files.ts",
      content: `import fs from "fs";
import path from "path";
import { Router } from "express";

const router = Router();

const UPLOAD_DIR = "/var/data/uploads";
const ALLOWED_FILES = new Set(["report.pdf", "summary.csv"]);

router.get("/files/:fileId", (req, res) => {
  const requested = path.basename(req.params.fileId);
  if (!ALLOWED_FILES.has(requested)) {
    return res.status(400).end();
  }
  const safePath = path.join(UPLOAD_DIR, requested);
  fs.readFile(safePath, (err, data) => {
    if (err) return res.status(404).end();
    res.send(data);
  });
});

export default router;
`
    },
    note: "Rule matches readFile/writeFile/createReadStream( ... req.|params.|query.|body. all within the same, non-nested parenthesis span. The negative resolves the untrusted segment (path.basename(req.params.fileId)) against an allowlist and joins it onto a fixed directory *before* calling fs.readFile, so the readFile(...) call itself only ever contains the local variable safePath — none of req./params./query./body. appear inside its parens."
  },
  {
    ruleId: "API_NO_OPENAPI_SPEC",
    check: "api",
    positive: {
      file: "src/routes/orders.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/orders", (req, res) => {
  res.json(listOrders());
});

router.post("/orders", (req, res) => {
  res.status(201).json(createOrder(req.body));
});

export default router;
`
    },
    negative: {
      file: "openapi.yaml",
      content: `openapi: "3.0.3"
info:
  title: Orders API
  version: "1.0.0"
paths:
  /orders:
    get:
      summary: List orders
      responses:
        "200":
          description: OK
    post:
      summary: Create an order
      responses:
        "201":
          description: Created
`
    },
    note: "checkApiSchemaDrift only flags API_NO_OPENAPI_SPEC when no file matches the openapi/swagger glob patterns anywhere in the repo AND route-call syntax is present. The corpus harness supplies exactly one file per case, so the honest way to represent 'the fix' is the file itself being a real openapi.yaml (fg matches it by name), which alone suppresses the finding — the harness can't express 'both the route file and the spec file coexist' in a single sample."
  },
  {
    ruleId: "API_PERMISSIVE_SCHEMA",
    check: "api",
    positive: {
      file: "openapi.yaml",
      content: `openapi: "3.0.3"
info:
  title: Users API
  version: "1.0.0"
paths:
  /users:
    post:
      summary: Create a user
      requestBody:
        content:
          application/json:
            schema:
              type: object
      responses:
        "201":
          description: Created
`
    },
    negative: {
      file: "openapi.yaml",
      content: `openapi: "3.0.3"
info:
  title: Users API
  version: "1.0.0"
paths:
  /users:
    post:
      summary: Create a user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              properties:
                name:
                  type: string
                  maxLength: 120
                email:
                  type: string
                  format: email
              required:
                - name
                - email
      responses:
        "201":
          description: Created
`
    },
    note: "Rule fires when the spec contains `type: object` with no `properties:` anywhere in the document. The negative adds an explicit properties map plus additionalProperties: false, exactly what requiredActions recommends, which flips the /properties:/ test to true and suppresses the finding."
  },
  {
    ruleId: "API_WEBHOOK_NO_SIGNATURE_VERIFY",
    check: "api",
    positive: {
      file: "src/routes/webhooks.ts",
      content: `import { Router } from "express";

const router = Router();

router.post("/webhooks/stripe", (req, res) => {
  const event = JSON.parse(req.body);
  handleStripeEvent(event);
  res.status(200).end();
});

export default router;
`
    },
    negative: {
      file: "src/routes/webhooks.ts",
      content: `import { Router } from "express";
import Stripe from "stripe";

const router = Router();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

router.post("/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return res.status(400).send("Webhook signature verification failed");
  }
  handleStripeEvent(event);
  res.status(200).end();
});

export default router;
`
    },
    note: "Positive: a POST route path containing 'webhook'/'stripe' with no signature-verification keyword anywhere in the repo. Negative calls stripe.webhooks.constructEvent, which matches the verifyHits pattern and is precisely the remediation requiredActions names."
  },
  {
    ruleId: "API_BATCH_AMPLIFICATION",
    check: "api",
    positive: {
      file: "src/routes/bulk.ts",
      content: `import { Router } from "express";

const router = Router();

router.post("/users/bulk-delete", async (req, res) => {
  for (const id of req.body.ids) {
    await db.users.deleteOne({ id });
  }
  res.status(200).json({ ok: true });
});

export default router;
`
    },
    negative: {
      file: "src/routes/bulk.ts",
      content: `import { Router } from "express";

const router = Router();
const MAX_BATCH_SIZE = 100;

router.post("/users/bulk-delete", async (req, res) => {
  const ids = req.body.ids;
  if (!Array.isArray(ids) || ids.length > MAX_BATCH_SIZE) {
    return res.status(413).json({ error: "Batch too large" });
  }
  for (const id of ids) {
    await db.users.deleteOne({ id });
  }
  res.status(200).json({ ok: true });
});

export default router;
`
    },
    note: "Positive iterates req.body.ids with no cap anywhere in the repo. Negative keeps the identical for-of over req.body.ids (so batchHits still fires) but adds a MAX_BATCH_SIZE constant and length check before the loop — the constant's name contains the literal substring 'MAX_BATCH', which the cap-detection regex matches, and it rejects with 413 exactly as requiredActions describes."
  },
  {
    ruleId: "API_FILTER_OPERATOR_INJECTION",
    check: "api",
    positive: {
      file: "src/routes/products.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/products", async (req, res) => {
  const results = await db.collection("products").find(req.query);
  res.json(results);
});

export default router;
`
    },
    negative: {
      file: "src/routes/products.ts",
      content: `import { Router } from "express";

const router = Router();
const ALLOWED_FILTER_FIELDS = new Set(["category", "inStock"]);

router.get("/products", async (req, res) => {
  const filter = {};
  for (const [key, value] of Object.entries(req.query)) {
    if (ALLOWED_FILTER_FIELDS.has(key) && typeof value === "string") {
      filter[key] = value;
    }
  }
  const results = await db.collection("products").find(filter);
  res.json(results);
});

export default router;
`
    },
    note: "Positive spreads req.query directly into find(...), matching find\\s*\\(\\s*req\\.query. Negative builds `filter` from an allowlist of permitted field names before calling find(filter) — the ORM call now only ever receives the local `filter` object, so the operator-injection regex never matches, exactly per requiredActions."
  },
  {
    ruleId: "API_NESTED_INCLUDE_FIELD_LEAK",
    check: "api",
    positive: {
      file: "src/routes/userDetail.ts",
      content: `import { Router } from "express";

const router = Router();

router.get("/users/:id", async (req, res) => {
  const include = req.query.include;
  const user = await db.users.findById(req.params.id).populate(include);
  res.json(user);
});

export default router;
`
    },
    negative: {
      file: "src/routes/userDetail.ts",
      content: `import { Router } from "express";

const router = Router();
const ALLOWED_INCLUDES = new Set(["profile", "orders"]);

router.get("/users/:id", async (req, res) => {
  const requested = req.query.include;
  const toInclude = typeof requested === "string" && ALLOWED_INCLUDES.has(requested) ? requested : undefined;
  const user = await db.users.findById(req.params.id).populate(toInclude);
  res.json(user);
});

export default router;
`
    },
    note: "Both samples read req.query.include (so includeHits fires in both), matching the rule's real design: the finding is suppressed only when an allowlist marker is present anywhere in the repo. The negative introduces ALLOWED_INCLUDES and validates the requested relation against it before passing it to populate(), matching requiredActions."
  },
  {
    ruleId: "API_SEQUENTIAL_ID_ENUMERATION",
    check: "api",
    positive: {
      file: "src/routes/userById.ts",
      content: `import { Router } from "express";

const router = Router();

const UserSchema = {
  id: { type: "INTEGER", primaryKey: true, autoIncrement: true },
  name: "STRING"
};

router.get("/users/:id", async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const user = await db.users.findByPk(userId);
  res.json(user);
});

export default router;
`
    },
    negative: {
      file: "src/routes/userById.ts",
      content: `import { Router } from "express";

const router = Router();

const UserSchema = {
  id: { type: "UUID", primaryKey: true, defaultValue: "uuidv4" },
  name: "STRING"
};

router.get("/users/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const user = await db.users.findByPk(id);
  if (!user || user.ownerOrgId !== req.session.orgId) {
    return res.status(404).json({ error: "Not found" });
  }
  res.json(user);
});

export default router;
`
    },
    note: "Rule requires BOTH an auto-increment schema marker and a parseInt/Number cast of a route id param. The negative switches the primary key to a UUID (no autoIncrement/INTEGER-primaryKey marker at all, so autoIncrementHits is empty) and reads the id via destructuring with no numeric cast, which is the exact non-sequential-identifier fix requiredActions recommends, plus adds real ownership authorization."
  },
  {
    ruleId: "API_DEPRECATED_VERSION_WEAK_AUTH",
    check: "api",
    positive: {
      file: "src/routes/index.ts",
      content: `import { Router } from "express";
import legacyV1Router from "./v1";

const router = Router();

// Legacy v1 endpoints, kept mounted for backwards compatibility.
router.use("/api/v1", legacyV1Router);

router.get("/api/v2/users", requireAuth, (req, res) => {
  res.json(listUsers());
});

export default router;
`
    },
    negative: {
      file: "src/routes/index.ts",
      content: `import { Router } from "express";

const router = Router();

// API v1 was fully decommissioned on 2025-01-01; all traffic now targets v2.
router.get("/api/v2/users", requireAuth, (req, res) => {
  res.json(listUsers());
});

export default router;
`
    },
    note: "This rule fires unconditionally once any router.use(/api/v1 or v0) mount (or a quoted /api/v1/ path) is found in the repo — it does not actually check auth strength on the legacy route, so the only genuine negative is retiring the legacy version outright rather than keeping it mounted under any guard. The negative removes the v1 mount entirely and keeps only v2, which is exactly requiredActions' 'retire deprecated API versions' guidance; it deliberately avoids the word 'deprecated' and any quoted '/api/v1' or '/v1/' path string so it does not accidentally match the detection regex."
  },
  {
    ruleId: "API_AUTH_TIMING_ORACLE",
    check: "api",
    positive: {
      file: "src/routes/login.ts",
      content: `import { Router } from "express";

const router = Router();

router.post("/login", async (req, res) => {
  const user = await db.users.findOne({ email: req.body.email });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const token = req.body.apiKey;
  if (token === user.apiKey) {
    return res.json({ ok: true });
  }
  res.status(401).json({ error: "Invalid credentials" });
});

export default router;
`
    },
    negative: {
      file: "src/routes/login.ts",
      content: `import { Router } from "express";
import { timingSafeEqual } from "crypto";

const router = Router();

router.post("/login", async (req, res) => {
  const user = await db.users.findOne({ email: req.body.email });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const provided = Buffer.from(req.body.apiKey ?? "", "utf8");
  const expected = Buffer.from(user.apiKey, "utf8");
  const matches = provided.length === expected.length && timingSafeEqual(provided, expected);
  if (matches) {
    return res.json({ ok: true });
  }
  res.status(401).json({ error: "Invalid credentials" });
});

export default router;
`
    },
    note: "Positive compares `token === user.apiKey` with ===, matching the naive-compare regex. Negative replaces the === comparison on the secret with crypto.timingSafeEqual over equal-length buffers, which is the exact requiredActions fix; the only remaining === in the file compares buffer lengths (provided.length === expected.length), whose left-hand identifier is not one of password/token/apiKey/secret/hash/otp so it does not match the rule's pattern."
  }
];
