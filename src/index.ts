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
        description:
          "Optional NVD API key.",
      }),
    ),

    requestTimeoutMs:
      Type.Optional(
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
     * Fresh evidence-first investigation
     * ------------------------------------------------------------
     */
    tool({
      name:
        "threatintel_investigate",

      label:
        "ThreatIntel Investigation",

      description:
        [
          "Investigate a cybersecurity target using authoritative threat intelligence sources.",
          "Currently supports CVE identifiers.",
          "Before performing a fresh investigation, check persisted investigation context.",
          "Reuse a prior investigation only when the deterministic freshness and completeness policy allows reuse.",
          "Otherwise perform a fresh investigation using NVD and CISA KEV.",
          "Fresh investigations are persisted automatically.",
          "For CVEs, retrieve evidence from NVD and CISA KEV.",
          "Return structured evidence including severity, CVSS, affected versions when explicitly available, CISA KEV status, evidence sources, confirmed facts, inferences, limitations, and SOC analyst guidance.",
          "Never invent facts.",
          "Never convert an unavailable source into a negative finding.",
          "CISA KEV states must distinguish listed, not-listed, and unknown.",
          "Use the returned structured fields as the source of truth.",
          "Treat verifications as authoritative claim-status metadata.",
          "Do not describe a claim as confirmed unless its verification state is confirmed.",
          "Treat contradicted claims as contradicted, not confirmed.",
          "Treat unknown claims as unknown, not negative findings.",
          "Clearly separate confirmed facts, analysis/inferences, and SOC guidance.",
          "Do not reinterpret conflicting evidence as fact; surface the conflict.",
        ].join(" "),

      parameters:
        Type.Object({
          target:
            Type.String({
              description:
                "Cybersecurity target to investigate. Currently use a CVE identifier such as CVE-2024-3094.",
            }),

          targetType:
            Type.Optional(
              Type.Union(
                [
                  Type.Literal(
                    "cve",
                  ),

                  Type.Literal(
                    "auto",
                  ),
                ],
                {
                  description:
                    "Target type. Use cve for a CVE identifier or auto when unsure.",
                },
              ),
            ),
        }),

      async execute(
        { target },
        config,
        context,
      ) {
        context.signal?.throwIfAborted();

        const execution =
          await investigateWithPriorPolicy(
            String(target),
            {
              nvdApiKey:
                config.nvdApiKey,

              requestTimeoutMs:
                config.requestTimeoutMs ??
                15000,
            },
          );

        if (
          execution.mode === "reused" &&
          execution.prior.context
        ) {
          return {
            mode: "reused",

            target:
              execution.prior.target,

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
          };
        }

        return {
          mode: "refreshed",

          investigation:
            execution.freshResult,

          persistence:
            execution.persistence,

          priorDecision:
            execution.prior.decision,
        };
      },
    }),

    /*
     * ------------------------------------------------------------
     * Prior investigation retrieval
     * ------------------------------------------------------------
     */
    tool({
      name:
        "threatintel_prior_investigation",

      label:
        "ThreatIntel Prior Investigation",

      description:
        [
          "Retrieve the latest persisted investigation for a cybersecurity target.",

          "Use this before performing a fresh investigation when prior intelligence may already exist.",

          "Returns the latest investigation metadata together with its persisted evidence, facts, and inferences.",

          "Use the returned context as prior evidence, not as a replacement for current authoritative source retrieval when freshness matters.",

          "If no prior investigation exists, the tool returns found=false.",

          "Never interpret the absence of a prior investigation as evidence that the target is safe or harmless.",
        ].join(" "),

      parameters:
        Type.Object({
          target:
            Type.String({
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