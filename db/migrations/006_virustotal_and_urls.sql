-- Apply after 005_indicator_lookups.sql. Safe to paste into the Supabase SQL editor; safe to run twice.
--
-- Indicator lookups gain VirusTotal as a service and full URLs as an indicator
-- type. Existing rows already satisfy the wider constraints.

BEGIN;

ALTER TABLE public.indicator_lookups DROP CONSTRAINT IF EXISTS indicator_lookups_type_check;
ALTER TABLE public.indicator_lookups ADD CONSTRAINT indicator_lookups_type_check
    CHECK (indicator_type IN ('ipv4', 'domain', 'url', 'md5', 'sha1', 'sha256'));

ALTER TABLE public.indicator_lookups DROP CONSTRAINT IF EXISTS indicator_lookups_source_check;
ALTER TABLE public.indicator_lookups ADD CONSTRAINT indicator_lookups_source_check
    CHECK (source IN ('internetdb', 'greynoise', 'abuseipdb', 'otx', 'virustotal'));

COMMIT;
