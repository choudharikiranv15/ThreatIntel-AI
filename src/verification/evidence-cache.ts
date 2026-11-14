import type { VendorImpactAssessment } from "../types.js";

/*
 * Tool results show only a few vendor rows, but a claim about one product must
 * be checked against every row. The plugin keeps the full rows of recent
 * investigations here, by CVE. Process memory only: after a restart the answer
 * check falls back to the rows in the tool result.
 */

const MAX_TARGETS = 200;

export type ProductRow = Pick<
    VendorImpactAssessment,
    "productName" | "packageName" | "status" | "cpe"
>;

const rowsByTarget = new Map<string, ProductRow[]>();

export function rememberVendorRows(
    target: string,
    rows: VendorImpactAssessment[] | undefined,
): void {
    const key = target.toUpperCase();

    rowsByTarget.delete(key);
    rowsByTarget.set(
        key,
        (rows ?? []).map((row) => ({
            productName: row.productName,
            packageName: row.packageName,
            status: row.status,
            cpe: row.cpe ?? null,
        })),
    );

    if (rowsByTarget.size > MAX_TARGETS) {
        rowsByTarget.delete(rowsByTarget.keys().next().value as string);
    }
}

export function vendorRowsFor(target: string): ProductRow[] | undefined {
    return rowsByTarget.get(target.toUpperCase());
}

export function clearVendorRows(): void {
    rowsByTarget.clear();
}
