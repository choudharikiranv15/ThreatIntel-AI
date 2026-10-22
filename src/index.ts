
import { Type } from "typebox";
import {
  defineToolPlugin,
} from "openclaw/plugin-sdk/tool-plugin";

import {
  getPriorInvestigation,
} from "./persistence/investigation-prior.js";

import {
  investigateWithPriorPolicy,
} from "./persistence/investigation-service.js";

export default defineToolPlugin({
  id: "threatintel-ai-engine",

  name: "ThreatIntel AI Engine",

  description:
    "Evidence-first threat intelligence investigation engine. Currently supports CVE investigations using NVD and CISA KEV, plus retrieval of previously persisted investigation context.",

  configSchema: Type.Object({
    nvdApiKey: Type.Optional(
      Type.String({
        description: "Optional NVD API key.",
      }),
    ),

    requestTimeoutMs: Type.Optional(
      Type.Number({
        description:
          "HTTP request timeout in milliseconds.",
        default: 15000,
        minimum: 1000,
        maximum: 60000,
      }),
    ),
  }),

  tools: (tool) => [
    /*
     * ------------------------------------------------------------
     * Evidence-first investigation with freshness-aware reuse
     * ------------------------------------------------------------
     */
    tool({
      name: "threatintel_investigate",

      label: "ThreatIntel Investigation",

      description: [
        "Investigate a cybersecurity target using authoritative threat intelligence sources.",
        "Currently supports CVE identifiers.",
        "Check persisted investigation context before performing a fresh investigation.",
        "Reuse prior results only when the deterministic freshness and completeness policy allows reuse.",
        "Set forceRefresh=true when the analyst explicitly requests fresh evidence.",
        "Otherwise perform a fresh investigation using NVD and CISA KEV when required.",
        "Fresh investigations are persisted automatically when persistence succeeds.",
        "Always report persistence failures explicitly; never claim that an investigation was saved when persistence failed.",
        "Return structured evidence including severity, CVSS, affected versions when explicitly available, CISA KEV status, evidence sources, confirmed facts, inferences, limitations, and SOC analyst guidance.",
        "Never invent facts.",
        "Never convert an unavailable or failed source into a negative finding.",
        "Distinguish CISA KEV listed, not-listed, and unknown states.",
        "Use returned structured fields as the source of truth.",
        "Treat verifications as authoritative claim-status metadata.",
        "Do not describe a claim as confirmed unless its verification state is confirmed.",
        "Treat contradicted claims as contradicted, not confirmed.",
        "Treat unknown claims as unknown, not negative findings.",
        "Clearly separate confirmed facts, analysis and inferences, and SOC guidance.",
        "Surface conflicting evidence instead of silently resolving conflicts.",
        "A reused investigation is historical persisted intelligence, not a guarantee that the target's current state has not changed.",
      ].join(" "),

      parameters: Type.Object({
        target: Type.String({
          description:
            "Cybersecurity target to investigate. Currently use a CVE identifier such as CVE-2024-3094.",
        }),

        targetType: Type.Optional(
          Type.Union(
            [
              Type.Literal("cve"),
              Type.Literal("auto"),
            ],
            {
              description:
                "Target type. Use cve for a CVE identifier or auto when unsure.",
            },
          ),
        ),

        forceRefresh: Type.Optional(
          Type.Boolean({
            description:
              "When true, bypass prior-result reuse and perform a fresh investigation.",
            default: false,
          }),
        ),
      }),

      async execute(
        { target, forceRefresh },
        config,
        context,
      ) {
        context.signal?.throwIfAborted();

        const execution =
          await investigateWithPriorPolicy(
            String(target),
            {
              nvdApiKey: config.nvdApiKey,

              requestTimeoutMs:
                config.requestTimeoutMs ?? 15000,

              forceRefresh: forceRefresh === true,
            },
          );

        context.signal?.throwIfAborted();

        if (
          execution.mode === "reused" &&
          execution.prior.context
        ) {
          return {
            mode: "reused",

            target: execution.prior.target,

            investigation:
              execution.prior.context.investigation,

            evidence:
              execution.prior.context.evidence,

            facts:
              execution.prior.context.facts,

            inferences:
              execution.prior.context.inferences,

            priorDecision:
              execution.prior.decision,

            persistence: {
              persisted: true,
              investigationId:
                execution.prior.latestInvestigation?.id ?? null,
              error: null,
              note:
                "Reused an existing persisted investigation; no new investigation was created.",
            },
          };
        }

        return {
          mode: "refreshed",

          target: execution.freshResult?.target ?? target,

          investigation: execution.freshResult,

          persistence: execution.persistence,

          priorDecision: execution.prior.decision,

          persistenceWarning:
            execution.persistence?.persisted === false
              ? "The fresh investigation completed, but persistence failed. Do not claim that this result was saved."
              : null,
        };
      },
    }),

    /*
     * ------------------------------------------------------------
     * Retrieve prior investigation
     * ------------------------------------------------------------
     */
    tool({
      name: "threatintel_prior_investigation",

      label: "ThreatIntel Prior Investigation",

      description: [
        "Retrieve the latest persisted investigation for a cybersecurity target.",
        "Use this tool to inspect historical intelligence and persisted evidence.",
        "Returns investigation metadata together with persisted evidence, facts, and inferences when available.",
        "Treat prior context as historical evidence, not as a replacement for fresh authoritative retrieval when freshness matters.",
        "If no prior investigation exists, the tool returns found=false.",
        "Never interpret the absence of a prior investigation as evidence that the target is safe or harmless.",
      ].join(" "),

      parameters: Type.Object({
        target: Type.String({
          description:
            "Cybersecurity target to search for in persisted investigation history, for example CVE-2024-3094.",
        }),
      }),

      async execute(
        { target },
        _config,
        context,
      ) {
        context.signal?.throwIfAborted();

        return await getPriorInvestigation(
          String(target),
        );
      },
    }),
  ],
});
