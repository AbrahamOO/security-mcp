/**
 * Per-provider AIMD concurrency control and rate-limit backoff.
 *
 * One limiter instance per provider, never one shared across all of them: Claude,
 * Codex, and Copilot have separate subscriptions and separate quotas, so throttling on
 * one must not stall the other two. That independence is the whole reason running three
 * fleets concurrently is the biggest throughput lever available here.
 */

export type LimiterState = {
  providerId: string;
  concurrency: number;
  maxConcurrency: number;
  inFlight: number;
  consecutiveSuccesses: number;
  consecutiveLimits: number;
  /** Epoch ms before which no new dispatch is permitted. */
  pausedUntil: number;
  totalDispatched: number;
  totalRateLimited: number;
  stalled: boolean;
};

export type BackoffConfig = { baseMs: number; maxMs: number; factor: number; jitter: number };

const MIN_CONCURRENCY = 1;
const SUCCESSES_BEFORE_INCREASE = 5;
/** Consecutive limits at concurrency 1 before a long cool-off. */
const LIMITS_BEFORE_LONG_PAUSE = 3;
const LONG_PAUSE_MS = 15 * 60 * 1000;
/** Beyond this we stop increasing pressure entirely, but never abandon the run. */
const LIMITS_BEFORE_STALL = 6;
const STALL_RETRY_MS = 30 * 60 * 1000;

export class ProviderLimiter {
  readonly state: LimiterState;
  private readonly backoff: BackoffConfig;
  private readonly now: () => number;

  constructor(providerId: string, maxConcurrency: number, backoff: BackoffConfig, now: () => number = Date.now) {
    this.backoff = backoff;
    this.now = now;
    this.state = {
      providerId,
      concurrency: Math.max(MIN_CONCURRENCY, maxConcurrency),
      maxConcurrency: Math.max(MIN_CONCURRENCY, maxConcurrency),
      inFlight: 0,
      consecutiveSuccesses: 0,
      consecutiveLimits: 0,
      pausedUntil: 0,
      totalDispatched: 0,
      totalRateLimited: 0,
      stalled: false
    };
  }

  /** Free dispatch slots right now. Zero while paused. */
  availableSlots(): number {
    if (this.now() < this.state.pausedUntil) return 0;
    return Math.max(0, this.state.concurrency - this.state.inFlight);
  }

  msUntilResume(): number {
    return Math.max(0, this.state.pausedUntil - this.now());
  }

  acquire(): void {
    this.state.inFlight++;
    this.state.totalDispatched++;
  }

  release(): void {
    this.state.inFlight = Math.max(0, this.state.inFlight - 1);
  }

  /** Additive increase: widen only after a sustained run of clean completions. */
  recordSuccess(): void {
    this.state.consecutiveLimits = 0;
    this.state.stalled = false;
    this.state.consecutiveSuccesses++;
    if (this.state.consecutiveSuccesses >= SUCCESSES_BEFORE_INCREASE) {
      this.state.consecutiveSuccesses = 0;
      this.state.concurrency = Math.min(this.state.maxConcurrency, this.state.concurrency + 1);
    }
  }

  /**
   * Multiplicative decrease plus a pause.
   *
   * In-flight children are deliberately NOT killed: they have already consumed their
   * quota, and killing them would waste it while producing nothing.
   */
  recordRateLimit(): { pausedMs: number; concurrency: number; stalled: boolean } {
    this.state.consecutiveSuccesses = 0;
    this.state.consecutiveLimits++;
    this.state.totalRateLimited++;
    this.state.concurrency = Math.max(MIN_CONCURRENCY, Math.floor(this.state.concurrency / 2));

    const n = this.state.consecutiveLimits;
    let pause = Math.min(this.backoff.maxMs, this.backoff.baseMs * Math.pow(this.backoff.factor, n - 1));

    if (n >= LIMITS_BEFORE_STALL) {
      // Never abandon a run: keep the queue intact and retry on a long cadence. Agents
      // stay `pending`, so the completion gate still refuses to call the run done.
      this.state.stalled = true;
      pause = STALL_RETRY_MS;
    } else if (n >= LIMITS_BEFORE_LONG_PAUSE && this.state.concurrency === MIN_CONCURRENCY) {
      pause = Math.max(pause, LONG_PAUSE_MS);
    }

    // Deterministic jitter is not required here, but unsynchronised retries across
    // three providers matter: without it they re-collide on the same boundary.
    const jitterFactor = 1 + (Math.random() * 2 - 1) * this.backoff.jitter;
    pause = Math.round(pause * jitterFactor);

    this.state.pausedUntil = this.now() + pause;
    return { pausedMs: pause, concurrency: this.state.concurrency, stalled: this.state.stalled };
  }

  /** A non-throttling failure: neither widen nor narrow. */
  recordFailure(): void {
    this.state.consecutiveSuccesses = 0;
  }

  /** Pause dispatch without treating it as throttling (e.g. auth lost). */
  pauseFor(ms: number): void {
    this.state.pausedUntil = Math.max(this.state.pausedUntil, this.now() + ms);
  }
}
