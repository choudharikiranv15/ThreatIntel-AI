import { Type } from "typebox";
import {
  defineToolPlugin,
} from "openclaw/plugin-sdk/tool-plugin";

import {
  investigateCve,
} from "./engine.js";

import {
  persistInvestigationResult,
} from "./persistence/index.js";

import {
  getPriorInvestigation,
} from "./persistence/investigation-prior.js";

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

          "For CVEs, retrieve evidence from NVD and CISA KEV.",

          "Return structured evidence including severity, CVSS, affected versions when explicitly available, CISA KEV status, evidence sources, confirmed facts, inferences, limitations, and SOC analyst guidance.",

          "Never invent facts.",

          "Never convert an unavailable source into a negative finding.",

          "CISA KEV states must distinguish listed, not-listed, and unknown.",

          "Use the returned structured fields as the source of truth.",
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

        const result =
          await investigateCve(
            String(target),
            {
              nvdApiKey:
                config.nvdApiKey,

              requestTimeoutMs:
                config.requestTimeoutMs ??
                15000,
            },
          );

        const persistence =
          await persistInvestigationResult(
            result,
          );

        return {
          ...result,

          persistence: {
            persisted:
              persistence.persisted,

            investigationId:
              persistence.investigationId,

            error:
              persistence.error,
          },
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