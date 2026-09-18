import type {
    ProviderResult,
} from "./types.js";

export type NvdProvider = (
    cveId: string,
) => Promise<ProviderResult>;

export type CisaKevProvider = (
    cveId: string,
) => Promise<ProviderResult>;

export type InvestigationProviders = {
    nvd: NvdProvider;
    cisaKev: CisaKevProvider;
};