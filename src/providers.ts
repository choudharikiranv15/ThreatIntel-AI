import type {
    ProviderResult,
} from "./types.js";

export type NvdProvider = (
    cveId: string,
) => Promise<ProviderResult>;

export type CisaKevProvider = (
    cveId: string,
) => Promise<ProviderResult>;

export type RedHatProvider = (
    cveId: string,
) => Promise<ProviderResult>;

export type OsvProvider = (
    cveId: string,
) => Promise<ProviderResult>;

export type InvestigationProviders = {
    nvd: NvdProvider;
    cisaKev: CisaKevProvider;
    redhat: RedHatProvider;

    /**
     * Enrichment. Null or unset means OSV was not checked, as in investigations
     * saved before it was added, which is different from it having no record.
     */
    osv?: OsvProvider | null;
};