-- Apply after 004_app_role.sql. Safe to paste into the Supabase SQL editor; safe to run twice.
--
-- One row per source per indicator lookup. The table is the cache (recent
-- answers are reused), the quota ledger (daily budgets per service and an
-- hourly limit per person), and the audit trail of what was sent where.

BEGIN;

CREATE TABLE IF NOT EXISTS public.indicator_lookups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    lookup_id uuid NOT NULL,
    indicator text NOT NULL,
    indicator_type text NOT NULL,
    source text NOT NULL,
    status text NOT NULL,
    facts jsonb,
    error text,
    reference text,
    -- True when this row reuses an earlier answer instead of calling the service.
    cached boolean NOT NULL DEFAULT false,
    requested_by text NOT NULL DEFAULT 'unknown',
    checked_at timestamp with time zone NOT NULL DEFAULT now(),

    CONSTRAINT indicator_lookups_type_check CHECK (indicator_type IN ('ipv4', 'domain', 'md5', 'sha1', 'sha256')),
    CONSTRAINT indicator_lookups_source_check CHECK (source IN ('internetdb', 'greynoise', 'abuseipdb', 'otx')),
    CONSTRAINT indicator_lookups_status_check CHECK (status IN (
        'success', 'observed_absence', 'not_configured', 'not_applicable',
        'budget_exhausted', 'rate_limited', 'timeout', 'error'
    ))
);

CREATE INDEX IF NOT EXISTS idx_indicator_lookups_cache
    ON public.indicator_lookups (indicator, source, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_indicator_lookups_budget
    ON public.indicator_lookups (source, checked_at) WHERE NOT cached;
CREATE INDEX IF NOT EXISTS idx_indicator_lookups_requester
    ON public.indicator_lookups (requested_by, checked_at);

ALTER TABLE public.indicator_lookups ENABLE ROW LEVEL SECURITY;

-- The plugin's least-privilege role (migration 004) gets this table too.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'threatintel_app') THEN
        GRANT SELECT, INSERT, DELETE ON public.indicator_lookups TO threatintel_app;
        DROP POLICY IF EXISTS threatintel_app_all ON public.indicator_lookups;
        CREATE POLICY threatintel_app_all ON public.indicator_lookups
            FOR ALL TO threatintel_app USING (true) WITH CHECK (true);
    END IF;
END
$$;

COMMIT;
