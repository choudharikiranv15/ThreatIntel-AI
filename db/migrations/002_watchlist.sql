-- Apply after 001_evidence_integrity.sql. Safe to paste into the Supabase SQL editor.
-- Runs in one transaction. Adds new tables only; existing tables are unchanged.

BEGIN;

-- One row per watched CVE. The row is also the schedule and the lock: a check
-- takes a lease with one atomic update, which works through Supabase's
-- connection pooler where advisory locks do not.
CREATE TABLE public.watchlist (
    target text PRIMARY KEY,
    enabled boolean NOT NULL DEFAULT true,
    interval_hours integer NOT NULL DEFAULT 24,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    created_by text,

    -- What each check is compared against. It only moves after a complete check.
    -- Deliberately not a foreign key: with ON DELETE SET NULL, deleting the
    -- baseline would silently restart monitoring. Without one, a missing
    -- baseline is detected and reported as an integrity warning.
    baseline_investigation_id uuid,

    last_checked_at timestamp with time zone,
    last_success_at timestamp with time zone,
    next_check_at timestamp with time zone NOT NULL DEFAULT now(),
    consecutive_failures integer NOT NULL DEFAULT 0,
    last_outcome text,
    last_error text,

    -- A failure alert is sent once per failing episode, not on every failed check.
    failure_alerted boolean NOT NULL DEFAULT false,

    lease_owner text,
    lease_expires_at timestamp with time zone,

    CONSTRAINT watchlist_target_check CHECK (target ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    CONSTRAINT watchlist_interval_check CHECK (interval_hours BETWEEN 6 AND 168)
);

CREATE INDEX idx_watchlist_due
    ON public.watchlist (next_check_at)
    WHERE enabled;

-- Detected events, saved before any delivery attempt. This table is the only
-- owner of delivery retries.
CREATE TABLE public.watch_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target text NOT NULL,
    check_id uuid NOT NULL,
    kind text NOT NULL,

    -- Identifies one observation of one change, so it is stored only once.
    fingerprint text NOT NULL,

    field text,
    scope text,
    before_value jsonb,
    after_value jsonb,
    explanation text NOT NULL,
    sources jsonb NOT NULL DEFAULT '[]'::jsonb,
    baseline_investigation_id uuid,
    investigation_id uuid,
    observed_at timestamp with time zone NOT NULL DEFAULT now(),

    deliverable boolean NOT NULL,
    delivery_status text NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamp with time zone,
    last_error text,
    sent_at timestamp with time zone,
    message_ids jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- Set when a send may have reached Discord before a crash.
    possible_duplicate boolean NOT NULL DEFAULT false,

    lease_owner text,
    lease_expires_at timestamp with time zone,

    CONSTRAINT watch_events_fingerprint_key UNIQUE (fingerprint),
    CONSTRAINT watch_events_kind_check CHECK (kind IN (
        'intelligence_change',
        'integrity_warning',
        'baseline_reset',
        'monitor_failure',
        'monitor_recovered'
    )),
    CONSTRAINT watch_events_delivery_status_check CHECK (delivery_status IN (
        'pending',
        'sending',
        'sent',
        'failed',
        'handed_off',
        'not_deliverable'
    ))
);

CREATE INDEX idx_watch_events_delivery
    ON public.watch_events (next_attempt_at)
    WHERE delivery_status IN ('pending', 'sending');

CREATE INDEX idx_watch_events_target
    ON public.watch_events (target, observed_at DESC);

-- As in migration 001: Supabase's Data API roles get no rows, the owner keeps access.
ALTER TABLE public.watchlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.watch_events ENABLE ROW LEVEL SECURITY;

COMMIT;
