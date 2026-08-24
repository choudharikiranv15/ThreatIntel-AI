import { investigateCve } from "./engine.js";

const result = await investigateCve("CVE-2024-3094", {
  requestTimeoutMs: 15000
});

console.log(JSON.stringify(result, null, 2));

if (!result.evidence.some((e) => e.source === "NVD")) {
  process.exitCode = 1;
}