import http from "node:http";

import { redactRequestBody, type RedactionStats, type Redactor } from "./redact.js";

/*
 * The privacy gateway: a loopback-only endpoint that OpenClaw uses as its
 * model provider. Each request's conversation is redacted, then forwarded to
 * the real provider; the response streams back untouched. It forwards only to
 * an allowlist of providers, only for local callers, and refuses what it
 * cannot parse rather than forwarding it unredacted.
 */

export const DEFAULT_UPSTREAMS: Record<string, string> = {
    openrouter: "https://openrouter.ai/api/v1",
    gemini: "https://generativelanguage.googleapis.com/v1beta/openai",
    groq: "https://api.groq.com/openai/v1",
    cerebras: "https://api.cerebras.ai/v1",
    mistral: "https://api.mistral.ai/v1",
    sarvam: "https://api.sarvam.ai/v1",
};

export type GatewaySettings = {
    port: number;
    upstreams: Record<string, string>;
    maxBodyBytes: number;
};

type Logger = { info: (message: string) => void; warn: (message: string) => void };

const DROP_REQUEST_HEADERS = new Set(["host", "content-length", "connection", "accept-encoding", "transfer-encoding", "keep-alive", "upgrade", "proxy-authorization", "forwarded", "x-forwarded-for"]);
const DROP_RESPONSE_HEADERS = new Set(["content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"]);

/** Only https provider addresses are allowed as upstreams. */
export function upstreamsFrom(overrides: Record<string, unknown> | undefined): Record<string, string> {
    const out: Record<string, string> = { ...DEFAULT_UPSTREAMS };

    for (const [name, url] of Object.entries(overrides ?? {})) {
        if (/^[a-z0-9-]{1,40}$/.test(name) && typeof url === "string" && /^https:\/\/[^\s/]+(\/[^\s]*)?$/.test(url)) {
            out[name] = url.replace(/\/+$/, "");
        }
    }

    return out;
}

const isLoopback = (address: string | undefined) => address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";

function fail(res: http.ServerResponse, status: number, message: string): void {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { message: `privacy gateway: ${message}`, type: "privacy_gateway" } }));
}

async function readBody(req: http.IncomingMessage, limit: number): Promise<Buffer | null> {
    const chunks: Buffer[] = [];
    let size = 0;

    for await (const chunk of req) {
        size += (chunk as Buffer).length;

        if (size > limit) return null;
        chunks.push(chunk as Buffer);
    }

    return Buffer.concat(chunks);
}

export function createGatewayHandler(
    settings: GatewaySettings,
    redactor: Redactor,
    logger: Logger,
    fetchImpl: typeof fetch = fetch,
): (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void> {
    const totals: RedactionStats = {};
    let requests = 0;

    return async (req, res) => {
        try {
            if (!isLoopback(req.socket.remoteAddress)) {
                return fail(res, 403, "local callers only");
            }

            const url = new URL(req.url ?? "/", "http://127.0.0.1");
            const [, name, ...rest] = url.pathname.split("/");
            const upstream = settings.upstreams[name ?? ""];

            if (!upstream || rest.length === 0) {
                return fail(res, 404, "unknown provider");
            }

            if (req.method !== "POST" && req.method !== "GET") {
                return fail(res, 405, "method not allowed");
            }

            const headers: Record<string, string> = {};

            for (const [key, value] of Object.entries(req.headers)) {
                if (!DROP_REQUEST_HEADERS.has(key) && typeof value === "string") headers[key] = value;
            }

            let body: string | undefined;

            if (req.method === "POST") {
                const raw = await readBody(req, settings.maxBodyBytes);

                if (raw === null) {
                    return fail(res, 413, "request too large");
                }

                let parsed: unknown;

                try {
                    parsed = JSON.parse(raw.toString("utf8"));
                } catch {
                    // Never forward what cannot be redacted.
                    return fail(res, 400, "request is not JSON; not forwarded");
                }

                if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
                    return fail(res, 400, "unexpected request shape; not forwarded");
                }

                const { body: redacted, stats } = redactRequestBody(parsed as Record<string, unknown>, redactor);

                for (const [kind, n] of Object.entries(stats)) {
                    totals[kind as keyof RedactionStats] = (totals[kind as keyof RedactionStats] ?? 0) + (n ?? 0);
                }

                body = JSON.stringify(redacted);
                headers["content-type"] = "application/json";
            }

            requests += 1;

            if (requests % 50 === 1) {
                // Counts only: what was redacted, never the content.
                logger.info(`threatintel privacy gateway: ${requests} requests; redacted so far ${JSON.stringify(totals)}`);
            }

            const response = await fetchImpl(`${upstream}/${rest.join("/")}${url.search}`, { method: req.method, headers, body });
            const outHeaders: Record<string, string> = {};

            response.headers.forEach((value, key) => {
                if (!DROP_RESPONSE_HEADERS.has(key)) outHeaders[key] = value;
            });

            res.writeHead(response.status, outHeaders);

            if (response.body) {
                for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
                    res.write(chunk);
                }
            }

            res.end();
        } catch {
            if (!res.headersSent) {
                fail(res, 502, "the provider could not be reached");
            } else {
                res.end();
            }
        }
    };
}

export function createPrivacyGatewayService(settings: GatewaySettings, redactor: Redactor) {
    let server: http.Server | null = null;

    return {
        id: "threatintel-privacy-gateway",
        async start(ctx: { logger?: Logger }) {
            const logger = ctx.logger ?? { info: () => undefined, warn: () => undefined };

            const handler = createGatewayHandler(settings, redactor, logger);

            server = http.createServer((req, res) => void handler(req, res));

            await new Promise<void>((resolve, reject) => {
                server!.once("error", reject);
                server!.listen(settings.port, "127.0.0.1", () => resolve());
            });

            logger.info(`threatintel privacy gateway listening on 127.0.0.1:${settings.port}`);
        },
        async stop() {
            await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
            server = null;
        },
    };
}
