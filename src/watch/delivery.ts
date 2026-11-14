import type { OpenClawConfig } from "openclaw/plugin-sdk/plugin-entry";

/*
 * Exactly one retry owner per alert.
 *
 * direct (default): sends without OpenClaw's delivery queue, so a failed send
 *   exists only in our outbox and only our outbox retries it.
 * openclaw_queue (fallback): OpenClaw keeps a failed send in its own queue and
 *   retries it on gateway start. Once it holds an alert, our outbox records the
 *   alert as handed off and never sends it again.
 */

export type DeliveryResult =
    | { status: "sent"; messageIds: string[] }
    | { status: "handed_off"; note: string }
    | { status: "failed"; error: string; sentBeforeError: boolean };

export type Deliverer = (text: string) => Promise<DeliveryResult>;

export type DeliveryMode = "direct" | "openclaw_queue";

function errorText(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

type OutcomeLike = {
    status?: string;
    sentBeforeError?: boolean;
};

function messageIdsOf(results: unknown[]): string[] {
    return results
        .map((result) => (result as { messageId?: unknown }).messageId)
        .filter((id): id is string => typeof id === "string" && id.length > 0);
}

/** The approved path: our outbox is the only retry owner. */
export function createDirectDeliverer(
    getConfig: () => OpenClawConfig,
    target: string,
): Deliverer {
    return async (text) => {
        const outcomes: OutcomeLike[] = [];

        try {
            const { deliverOutboundPayloads } = await import(
                "openclaw/plugin-sdk/outbound-runtime"
            );

            const results = await deliverOutboundPayloads({
                cfg: getConfig(),
                channel: "discord",
                to: target,
                payloads: [{ text }],
                // Keeps the message out of OpenClaw's own retry queue.
                skipQueue: true,
                onPayloadDeliveryOutcome: (outcome: OutcomeLike) => {
                    outcomes.push(outcome);
                },
            });

            const messageIds = messageIdsOf(results ?? []);

            // Delivery reported success without a message: treat as failed, not sent.
            return messageIds.length > 0
                ? { status: "sent", messageIds }
                : {
                    status: "failed",
                    error: "Discord returned no message id.",
                    sentBeforeError: false,
                };
        } catch (error) {
            return {
                status: "failed",
                error: errorText(error),
                sentBeforeError: outcomes.some((outcome) => outcome.sentBeforeError === true),
            };
        }
    };
}

/**
 * The fallback. Ownership moves to OpenClaw only when its queue has the alert:
 * a failure before queueing stays ours to retry.
 */
export function createQueueDeliverer(
    getConfig: () => OpenClawConfig,
    target: string,
): Deliverer {
    return async (text) => {
        try {
            const { sendDurableMessageBatch } = await import(
                "openclaw/plugin-sdk/channel-message-runtime"
            );

            const result = await sendDurableMessageBatch({
                cfg: getConfig(),
                channel: "discord",
                to: target,
                payloads: [{ text }],
            });

            if (result.status === "sent" || result.status === "partial_failed") {
                return { status: "sent", messageIds: messageIdsOf(result.results) };
            }

            if (result.status === "suppressed") {
                return {
                    status: "failed",
                    error: `Delivery suppressed: ${result.reason}`,
                    sentBeforeError: false,
                };
            }

            return result.stage === "queue"
                ? {
                    status: "failed",
                    error: `Not queued: ${errorText(result.error)}`,
                    sentBeforeError: false,
                }
                : {
                    status: "handed_off",
                    note: `OpenClaw's delivery queue now owns retries: ${errorText(result.error)}`,
                };
        } catch (error) {
            return {
                status: "failed",
                error: errorText(error),
                sentBeforeError: false,
            };
        }
    };
}
