-- Apply after 006_virustotal_and_urls.sql. Safe to paste into the Supabase SQL editor; safe to run twice.
--
-- One row per MXToolbox DNS check made during an email header analysis: the
-- cache (records are reused for a day), the quota ledger (the free plan allows
-- 64 DNS lookups a day), and the record of what was sent. Only the sender
-- domain and the check's result are stored; the headers themselves never are.

BEGIN;

CREATE TABLE IF NOT EXISTS public.mail_checks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id uuid NOT NULL,
    command text NOT NULL,
    -- The domain, or "domain:selector" for DKIM.
    argument text NOT NULL,
    status text NOT NULL,
    facts jsonb,
    error text,
    reference text,
    cached boolean NOT NULL DEFAULT false,
    requested_by text NOT NULL DEFAULT 'unknown',
    checked_at timestamp with time zone NOT NULL DEFAULT now(),

    CONSTRAINT mail_checks_command_check CHECK (command IN ('spf', 'dmarc', 'dkim')),
    CONSTRAINT mail_checks_status_check CHECK (status IN (
        'success', 'not_configured', 'budget_exhausted', 'rate_limited', 'timeout', 'error'
    ))
);

CREATE INDEX IF NOT EXISTS idx_mail_checks_cache
    ON public.mail_checks (command, argument, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_mail_checks_budget
    ON public.mail_checks (checked_at) WHERE NOT cached;
CREATE INDEX IF NOT EXISTS idx_mail_checks_requester
    ON public.mail_checks (requested_by, checked_at);

ALTER TABLE public.mail_checks ENABLE ROW LEVEL SECURITY;

-- The plugin's least-privilege role (migration 004) gets this table too.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'threatintel_app') THEN
        GRANT SELECT, INSERT, DELETE ON public.mail_checks TO threatintel_app;
        DROP POLICY IF EXISTS threatintel_app_all ON public.mail_checks;
        CREATE POLICY threatintel_app_all ON public.mail_checks
            FOR ALL TO threatintel_app USING (true) WITH CHECK (true);
    END IF;
END
$$;

COMMIT;
