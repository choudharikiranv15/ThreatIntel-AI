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
