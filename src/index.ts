import { Type } from "typebox";
import {
  defineToolPlugin,
} from "openclaw/plugin-sdk/tool-plugin";

import {
  investigateCve,
} from "./engine.js";

export default defineToolPlugin({
  id: "threatintel-ai-engine",

  name: "ThreatIntel AI Engine",

  description:
    "Evidence-first threat intelligence investigation engine. Currently supports CVE investigations using NVD and CISA KEV. The tool is the authoritative evidence-gathering layer. The model must not invent, infer, or replace source-backed facts with generic web knowledge.",

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

        return result;
      },
    }),
  ],
});