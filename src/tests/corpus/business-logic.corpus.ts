import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "MASS_ASSIGNMENT",
    check: "business-logic",
    positive: {
      file: "src/routes/users.ts",
      content: `export async function updateUser(req, res) {\n  await User.update(req.body, { where: { id: req.params.id } });\n  return res.json({ ok: true });\n}\n`
    },
    negative: {
      file: "src/routes/users.ts",
      content: `export async function updateUser(req, res) {\n  const allowed = pick(req.body, ["name", "email"]);\n  await User.update(allowed, { where: { id: req.params.id } });\n  return res.json({ ok: true });\n}\n`
    },
    note: "Positive spreads req.body straight into update(); the regex requires update(/create(/new X( to be immediately followed by req.body|body. Negative picks an explicit allowlist first, so update()'s argument is `allowed`, not req.body/body, and the call never matches the sink pattern."
  },
  {
    ruleId: "IDOR_DIRECT_ACCESS",
    check: "business-logic",
    positive: {
      file: "src/routes/accounts.ts",
      content: `export async function getAccount(req, res) {\n  const { params } = req;\n  const record = await Account.findById(params.id);\n  return res.json(record);\n}\n`
    },
    negative: {
      file: "src/routes/accounts.ts",
      content: `export async function getAccount(req, res) {\n  const { params } = req;\n  const record = await Account.findById(params.id, { userId: req.user.id });\n  return res.json(record);\n}\n`
    },
    note: "findById(params.id) matches the direct-lookup pattern (prefix params. + suffix id). The safe-list check is per matched line, so the ownership scope must appear on that same line: passing { userId: req.user.id } into the same findById call trips the req\\.user\\??\\.id safe marker and suppresses the finding."
  },
  {
    ruleId: "IDOR_MULTI_LINE",
    check: "business-logic",
    positive: {
      file: "src/routes/documents.ts",
      content: `export async function getDocument(req, res) {\n  const recordId = req.params.id;\n  const record = await Document.findOne(recordId);\n  return res.json(record);\n}\n`
    },
    negative: {
      file: "src/routes/documents.ts",
      content: `export async function getDocument(req, res) {\n  const recordId = req.params.id;\n  const record = await Document.findOne({ id: recordId, userId: req.user.id });\n  return res.json(record);\n}\n`
    },
    note: "The two-pass IDOR check pairs a req.params.<x> assignment with a findOne/findById call using that same variable within 15 lines. The negative keeps the same shape but scopes the lookup with userId: req.user.id on the lookup line itself, which the checker's safeRe check excludes before pairing."
  },
  {
    ruleId: "NEGATIVE_AMOUNT_BYPASS",
    check: "business-logic",
    positive: {
      file: "src/services/wallet.ts",
      content: `export async function credit(account, req) {\n  account.balance += req.body.amount;\n  await account.save();\n}\n`
    },
    negative: {
      file: "src/services/wallet.ts",
      content: `export async function credit(account, req) {\n  const amount = z.number().positive().parse(req.body.amount);\n  account.balance += amount;\n  await account.save();\n}\n`
    },
    note: "Positive adds an unvalidated req.body.amount straight onto balance. Negative parses it through z.number().positive() first, so the line that actually mutates balance reads from the local `amount` variable, not req./body., and never matches the amount-source pattern at all."
  },
  {
    ruleId: "RACE_CONDITION_BALANCE",
    check: "business-logic",
    positive: {
      file: "src/services/ledger.ts",
      content: `export async function decrementBalance(accountId: string, amount: number) {\n  await Account.findOne({ id: accountId }).then((a) => (a.balance -= amount, a.save()));\n}\n`
    },
    negative: {
      file: "src/services/ledger.ts",
      content: `export async function decrementBalance(accountId: string, amount: number) {\n  await db.$transaction([db.account.update({ where: { id: accountId }, data: { balance: { decrement: amount } } })]);\n}\n`
    },
    note: "The single-line rule requires findOne/findById/findUnique, balance, and update/save to co-occur (in that order) on one source line, which is why the vulnerable read-modify-write is written as one chained expression. The negative removes the separate read entirely and uses an atomic $transaction decrement, so it contains no findOne/findById/findUnique at all."
  },
  {
    ruleId: "RACE_CONDITION_TOCTOU",
    check: "business-logic",
    positive: {
      file: "src/services/transfer.ts",
      content: `export async function transferOut(accountId: string, amount: number) {\n  const account = await Account.findOne({ id: accountId });\n  account.balance -= amount;\n  await account.save();\n}\n`
    },
    negative: {
      file: "src/services/transfer.ts",
      content: `export async function transferOut(accountId: string, amount: number) {\n  await Account.update({ id: accountId }, { $inc: { balance: -amount } });\n}\n`
    },
    note: "Positive reads the account on one line then writes it several lines later using the same variable, the exact read-then-write TOCTOU shape the two-pass matcher pairs. Negative drops the separate read and performs a single atomic $inc update; the write line itself contains \\$inc, which the check's safeRe excludes before any read/write pairing is attempted."
  },
  {
    ruleId: "FILESYSTEM_TOCTOU",
    check: "business-logic",
    positive: {
      file: "src/utils/cleanup.ts",
      content: `export function deleteIfExists(path: string) {\n  fs.access(path, (err) => {\n    if (!err) {\n      fs.unlink(path, () => {});\n    }\n  });\n}\n`
    },
    negative: {
      file: "src/utils/cleanup.ts",
      content: `export function createIfNotExists(path: string, data: string) {\n  fs.open(path, 'wx', (err, fd) => {\n    if (err) return;\n    fs.writeFile(fd, data, () => {});\n  });\n}\n`
    },
    note: "Positive checks fs.access then fs.unlink a few lines later, the check-then-act pattern. Negative uses fs.open with the 'wx' flag (atomic create-or-fail) and has no fs.access/fs.stat/fs.exists call anywhere in the file, so there is no read event for the matcher to pair with any write."
  },
  {
    ruleId: "HARDCODED_CREDENTIALS",
    check: "business-logic",
    positive: {
      file: "src/config/payments.ts",
      content: `export const paymentsConfig = {\n  apiKey: "sk_live_51H8x9abcdEFGh",\n};\n`
    },
    negative: {
      file: "src/config/payments.ts",
      content: `export const paymentsConfig = {\n  apiKey: process.env.PAYMENTS_API_KEY,\n};\n`
    },
    note: "Positive assigns a quoted 20+ char literal to apiKey. Negative reads from process.env, which fails the quoted-string-literal requirement entirely (no ['\"] literal follows the colon), so the rule's regex has nothing to match."
  },
  {
    ruleId: "MISSING_ADMIN_ROUTE_AUTH",
    check: "business-logic",
    positive: {
      file: "src/routes/admin.ts",
      content: `router.get('/admin/users', listUsersHandler);\n`
    },
    negative: {
      file: "src/routes/admin.ts",
      content: `router.get('/admin/users', requireAuth, requireRole('admin'), listUsersHandler);\n`
    },
    note: "Both lines register an /admin/ route and match the base pattern. Negative adds requireAuth on the same registration line, which the authRe safe-list matches, suppressing the finding; positive has no auth middleware reference anywhere on the line."
  },
  {
    ruleId: "TIMING_ORACLE_COMPARISON",
    check: "business-logic",
    positive: {
      file: "src/auth/otp.ts",
      content: `export function verifyOtp(req, res) {\n  if (expectedOtp === req.body.otp) {\n    return res.json({ verified: true });\n  }\n  return res.status(401).end();\n}\n`
    },
    negative: {
      file: "src/auth/otp.ts",
      content: `export function verifyOtp(req, res) {\n  const a = Buffer.from(String(expectedOtp));\n  const b = Buffer.from(String(req.body.otp));\n  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {\n    return res.json({ verified: true });\n  }\n  return res.status(401).end();\n}\n`
    },
    note: "Positive compares an OTP-like value with === directly against req.body.otp. Negative buffers both sides and uses crypto.timingSafeEqual(); the comparison line no longer has an otp/pin/token-family identifier immediately followed by ===/== against a req./body./stored value, so the pattern never matches."
  },
  {
    ruleId: "MONETARY_FLOAT_ARITHMETIC",
    check: "business-logic",
    positive: {
      file: "src/services/checkout.ts",
      content: `export function computeTotal(price: number) {\n  const total = price * 1.08;\n  return total;\n}\n`
    },
    negative: {
      file: "src/services/checkout.ts",
      content: `export function computeTotal(priceCents: number) {\n  const totalCents = Math.round(priceCents * 100);\n  return totalCents;\n}\n`
    },
    note: "Positive multiplies price by a float literal (1.08), matching the price\\s*\\*\\s*\\d+\\.\\d+ pattern. Negative works in integer cents and multiplies by the whole number 100, which is not a \\d+\\.\\d+ float literal and doesn't contain rate/percent/factor, so it never matches the float-arithmetic shape at all."
  },
  {
    ruleId: "VOUCHER_REPLAY_RISK",
    check: "business-logic",
    positive: {
      file: "src/services/vouchers.ts",
      content: `export async function redeemVoucher(code: string) {\n  const voucher = await Voucher.findOne({ code });\n  voucher.usedAt = new Date();\n  await voucher.save();\n}\n`
    },
    negative: {
      file: "src/services/vouchers.ts",
      content: `export async function applyCode(code: string, userId: string) {\n  const record = await db.redemption.findUnique({ where: { code_userId: { code, userId } } });\n  if (record) throw new Error('voucher code already redeemed');\n  await db.redemption.create({ data: { code, userId } });\n}\n`
    },
    note: "Positive's declaration line and its 'voucher.usedAt = new Date()' line both mention voucher without any idempotency marker (usedAt is set, not checked) — an in-memory assignment before persistence, which does not stop a concurrent replay. Negative's only 'voucher/redeem'-matching line is the throw guarded by `if (record) throw ... already redeemed`, which the idempotencyRe check recognizes as a genuine check-before-grant."
  },
  {
    ruleId: "BIZ_CLIENT_SUPPLIED_TOTAL",
    check: "business-logic",
    positive: {
      file: "src/routes/checkout.ts",
      content: `export async function checkout(req, res) {\n  const result = await processPayment(req.body.total);\n  return res.json(result);\n}\n`
    },
    negative: {
      file: "src/routes/checkout.ts",
      content: `export async function checkout(req, res) {\n  const total = await computeCartTotal(req.user.id);\n  const result = await processPayment(total);\n  return res.json(result);\n}\n`
    },
    note: "Positive passes req.body.total straight into processPayment(). Negative computes the total server-side from the authoritative cart and passes the local `total` variable instead, so processPayment()'s argument is no longer a req./body./params.-prefixed amount and the rule (which has no safe-list, only a structural match) never fires."
  },
  {
    ruleId: "BIZ_ORDER_FULFILLMENT_BYPASS",
    check: "business-logic",
    positive: {
      file: "src/routes/orders.ts",
      content: `export async function updateOrder(req, res) {\n  order.status = req.body.status;\n  await order.save();\n}\n`
    },
    negative: {
      file: "src/routes/orders.ts",
      content: `export async function updateOrder(req, res) {\n  order.status = await stripe.paymentIntents.retrieve(paymentIntentId).then(pi => pi.status);\n  await order.save();\n}\n`
    },
    note: "Positive assigns order.status directly from req.body.status. Negative derives status from Stripe's payment intent instead, so the assignment's right-hand side is no longer req./body./params./query.-prefixed and the pattern doesn't match at all."
  },
  {
    ruleId: "BIZ_WALLET_NONATOMIC_DECREMENT",
    check: "business-logic",
    positive: {
      file: "src/services/wallet-balance.ts",
      content: `export function spend(wallet, amount) {\n  wallet.balance = wallet.balance - amount;\n  return wallet;\n}\n`
    },
    negative: {
      file: "src/services/wallet-balance.ts",
      content: `export async function spend(walletId: string, amount: number) {\n  return db.wallet.update({ where: { id: walletId, balance: { gte: amount } }, data: { balance: { decrement: amount } } });\n}\n`
    },
    note: "Positive reassigns wallet.balance from a prior read (wallet.balance - amount), matching the read-modify-write shape. Negative issues a single conditional DB update where the where-clause requires balance >= amount and the write uses Prisma's decrement operator; the {decrement safe marker on that line suppresses the finding."
  },
  {
    ruleId: "BIZ_REFUND_WITHOUT_PAID_PURCHASE",
    check: "business-logic",
    positive: {
      file: "src/services/refunds.ts",
      content: `export async function refund(orderId: string, amount: number) {\n  await issueRefund(orderId, amount);\n}\n`
    },
    negative: {
      file: "src/services/refunds.ts",
      content: `export async function refund(orderId: string, order: any) {\n  if (order.status === 'paid' && !order.refundedAt) await issueRefund(orderId, order.amountPaid);\n}\n`
    },
    note: "Positive calls issueRefund() with no check that the order was ever paid. Negative guards the same call with `order.status === 'paid'` on the identical line, which matches the safeRe status==='paid' marker and suppresses the finding."
  },
  {
    ruleId: "BIZ_BULK_OP_NOT_TENANT_SCOPED",
    check: "business-logic",
    positive: {
      file: "src/services/records.ts",
      content: `export async function purgeExpired() {\n  await db.record.deleteMany({ where: { status: 'expired' } });\n}\n`
    },
    negative: {
      file: "src/services/records.ts",
      content: `export async function purgeExpired(req) {\n  await db.record.deleteMany({ where: { status: 'expired', tenantId: req.user.tenantId } });\n}\n`
    },
    note: "Both lines call deleteMany(), matching the bulk-op pattern. Negative's where-clause includes `tenantId: req.user.tenantId` on the same line, matching the tenantId[:=] safe marker; positive's where-clause has no tenant/user/account scoping at all."
  },
  {
    ruleId: "BIZ_WITHDRAWAL_LIMIT_RACE",
    check: "business-logic",
    positive: {
      file: "src/services/withdrawals.ts",
      content: `export async function withdraw(userId: string, amount: number) {\n  const todayTotal = await getTodayWithdrawalTotal(userId);\n  if (todayTotal + amount > dailyWithdrawalLimit) throw new Error('Limit exceeded');\n  await processWithdrawal(userId, amount);\n}\n`
    },
    negative: {
      file: "src/services/withdrawals.ts",
      content: `export async function withdraw(userId: string, amount: number) {\n  const key = "withdrawals:" + userId;\n  if ((await redisClient.incrby(key, amount)) > dailyWithdrawalLimit) throw new Error('Limit exceeded');\n  await processWithdrawal(userId, amount);\n}\n`
    },
    note: "Positive checks a separately-read running total against dailyWithdrawalLimit with no atomic guard on that line. Negative folds the increment and the limit check into one redis.incrby() expression on the same line, matching the redis.*incr safe marker, so the limit comparison is now backed by an atomic counter rather than a read-then-compare."
  },
  {
    ruleId: "BIZ_INVENTORY_UNDERFLOW",
    check: "business-logic",
    positive: {
      file: "src/services/inventory.ts",
      content: `export function reserveStock(product, quantity) {\n  product.stock -= quantity;\n  return product;\n}\n`
    },
    negative: {
      file: "src/services/inventory.ts",
      content: `export async function decrementStock(id: string, qty: number) {\n  const result = await db.query('UPDATE product SET stock = stock - $1 WHERE id = $2 AND stock >= $1', [qty, id]);\n  if (result.rowCount === 0) throw new Error('Insufficient stock');\n}\n`
    },
    note: "Positive decrements stock with an unguarded -= that can drive it negative under concurrent orders. Negative issues a single conditional SQL UPDATE whose WHERE clause requires stock >= qty on the same line, matching the WHERE...stock>= safe marker, and rejects the order when no row is affected."
  },
  {
    ruleId: "BIZ_PAYMENT_NO_IDEMPOTENCY",
    check: "business-logic",
    positive: {
      file: "src/services/billing.ts",
      content: `export async function charge(amount: number, currency: string) {\n  return stripe.paymentIntents.create({ amount, currency });\n}\n`
    },
    negative: {
      file: "src/services/billing.ts",
      content: `export async function charge(amount: number, currency: string, orderId: string) {\n  return stripe.paymentIntents.create({ amount, currency }, { idempotencyKey: orderId });\n}\n`
    },
    note: "Both lines call stripe.paymentIntents.create(). Negative passes an idempotencyKey option derived from the order ID on the same call, matching the idempotencyKey safe marker; positive has no idempotency key anywhere, so a retry or replay would create a duplicate charge."
  }
];
