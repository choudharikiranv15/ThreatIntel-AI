/**
 * Ends a provider request on timeout, or when the caller aborts the tool call.
 */
export function requestSignal(
  timeoutMs: number,
  signal?: AbortSignal,
): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);

  return signal
    ? AbortSignal.any([timeout, signal])
    : timeout;
}

/**
 * How hard to retry a transient provider failure. Retries never change what a
 * final failure means: after the last attempt it is still an error or timeout,
 * never an absence.
 */
export type RetryPolicy = {
  /** Total attempts, including the first. */
  attempts: number;

  /** Longest single wait, including a server's Retry-After. */
  maxDelayMs: number;

  /** No retry starts once this much time has passed since the first attempt. */
  budgetMs: number;
};

/* An analyst is waiting, so one quick retry. */
export const INTERACTIVE_RETRY: RetryPolicy = {
  attempts: 2,
  maxDelayMs: 2_000,
  budgetMs: 8_000,
};

/* Scheduled monitoring can afford to wait out a rate limit. */
export const MONITOR_RETRY: RetryPolicy = {
  attempts: 3,
  maxDelayMs: 30_000,
  budgetMs: 90_000,
};

const RETRYABLE_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

const TRANSIENT_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EAI_AGAIN",
  "ENOTFOUND",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_SOCKET",
]);

function isTransientError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return true;
  }

  const code = (error as { cause?: { code?: unknown } } | null)?.cause?.code;

  // fetch reports network failures as a TypeError carrying the system code.
  return (
    error instanceof TypeError ||
    (typeof code === "string" && TRANSIENT_CODES.has(code))
  );
}

function retryAfterMs(response: Response): number | undefined {
  const header = response.headers.get("retry-after");

  if (!header) {
    return undefined;
  }

  const seconds = Number(header);

  if (Number.isFinite(seconds)) {
    return Math.max(0, seconds * 1000);
  }

  const date = Date.parse(header);

  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : undefined;
}

function backoffMs(attempt: number, policy: RetryPolicy): number {
  const base = Math.min(policy.maxDelayMs, 500 * 2 ** (attempt - 1));

  return base + Math.floor(Math.random() * 250);
}

function wait(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }

    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);

    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };

    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export type FetchWithRetryOptions = {
  timeoutMs: number;
  signal?: AbortSignal;
  retry?: RetryPolicy;
  /** Test seam; production uses real timers. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
};

/**
 * fetch, retrying timeouts, network errors, and HTTP 408/425/429/5xx with
 * backoff that respects Retry-After. Each attempt gets its own timeout. The
 * final response or error is returned unchanged, so callers keep their own
 * handling of 404 (absence) and other statuses.
 */
export async function fetchWithRetry(
  url: string,
  init: Omit<RequestInit, "signal">,
  options: FetchWithRetryOptions,
): Promise<Response> {
  const policy = options.retry ?? INTERACTIVE_RETRY;
  const sleep = options.sleep ?? wait;
  const started = Date.now();

  for (let attempt = 1; ; attempt += 1) {
    let delay: number;

    try {
      const response = await fetch(url, {
        ...init,
        signal: requestSignal(options.timeoutMs, options.signal),
      });

      if (
        !RETRYABLE_STATUSES.has(response.status) ||
        attempt >= policy.attempts
      ) {
        return response;
      }

      delay = Math.min(
        policy.maxDelayMs,
        retryAfterMs(response) ?? backoffMs(attempt, policy),
      );

      if (Date.now() - started + delay > policy.budgetMs) {
        return response;
      }

      await response.body?.cancel().catch(() => undefined);
    } catch (error) {
      // A caller's abort is final; so are errors a retry cannot fix.
      if (
        options.signal?.aborted ||
        attempt >= policy.attempts ||
        !isTransientError(error)
      ) {
        throw error;
      }

      delay = backoffMs(attempt, policy);

      if (Date.now() - started + delay > policy.budgetMs) {
        throw error;
      }
    }

    await sleep(delay, options.signal);
  }
}
