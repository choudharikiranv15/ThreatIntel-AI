-- Apply after 002_watchlist.sql. Safe to paste into the Supabase SQL editor.
-- Runs in one transaction. Adds the threat feed tables and lets feed posts use
-- the existing watch_events outbox, so one delivery and retry system serves both.

BEGIN;

-- Feed posts go to their own channel. Existing rows are watch alerts.
ALTER TABLE public.watch_events
    ADD COLUMN channel text NOT NULL DEFAULT 'watch',
    -- The rendered post, fixed when it is selected, so what was decided is what is sent.
    ADD COLUMN message text,
    ADD CONSTRAINT watch_events_channel_check CHECK (channel IN ('watch', 'feed'));

ALTER TABLE public.watch_events DROP CONSTRAINT watch_events_kind_check;
ALTER TABLE public.watch_events ADD CONSTRAINT watch_events_kind_check CHECK (kind IN (
    'intelligence_change',
    'integrity_warning',
    'baseline_reset',
    'monitor_failure',
    'monitor_recovered',
    'threat_feed'
));

-- The feed's schedule and lock: one row, leased with one atomic update, as the watchlist does.
CREATE TABLE public.feed_state (
    id smallint PRIMARY KEY DEFAULT 1,
    next_run_at timestamp with time zone NOT NULL DEFAULT now(),
    last_run_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_published_at timestamp with time zone,
    consecutive_failures integer NOT NULL DEFAULT 0,
    last_error text,
    lease_owner text,
    lease_expires_at timestamp with time zone,
    CONSTRAINT feed_state_single_row CHECK (id = 1)
);

INSERT INTO public.feed_state (id) VALUES (1);

-- One row per collection cycle, for status and troubleshooting.
CREATE TABLE public.feed_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at timestamp with time zone NOT NULL DEFAULT now(),
    finished_at timestamp with time zone,
    status text NOT NULL DEFAULT 'running',
    duration_ms integer,
    discovered integer NOT NULL DEFAULT 0,
    new_items integer NOT NULL DEFAULT 0,
    updated_items integer NOT NULL DEFAULT 0,
    filtered integer NOT NULL DEFAULT 0,
    duplicates_suppressed integer NOT NULL DEFAULT 0,
    selected integer NOT NULL DEFAULT 0,
    deferred integer NOT NULL DEFAULT 0,
    -- Per source: status, item count, error, duration.
    providers jsonb NOT NULL DEFAULT '[]'::jsonb,
    error text,
    CONSTRAINT feed_runs_status_check CHECK (status IN ('running', 'success', 'partial', 'failed'))
);

CREATE INDEX idx_feed_runs_started ON public.feed_runs (started_at DESC);

-- One row per advisory or article, keyed by source and the source's own id.
CREATE TABLE public.feed_items (
    item_key text PRIMARY KEY,
    source text NOT NULL,
    title text NOT NULL,
    url text NOT NULL,
    published_at timestamp with time zone,
    first_seen_at timestamp with time zone NOT NULL DEFAULT now(),
    last_seen_at timestamp with time zone NOT NULL DEFAULT now(),
    retrieved_at timestamp with time zone NOT NULL DEFAULT now(),

    cves text[] NOT NULL DEFAULT '{}',
    products text[] NOT NULL DEFAULT '{}',
    platforms text[] NOT NULL DEFAULT '{}',
    iocs jsonb NOT NULL DEFAULT '[]'::jsonb,
    severity text NOT NULL DEFAULT 'unknown',
    exploitation text NOT NULL DEFAULT 'none',

    priority text NOT NULL,
    confidence text NOT NULL,
    reasons jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- Hash of the fields whose change makes an item worth reconsidering.
    content_hash text NOT NULL,
    state text NOT NULL,
    state_reason text,
    published_hash text,
    last_published_at timestamp with time zone,
    published_exploitation text,
    published_ioc_count integer,
    expires_at timestamp with time zone NOT NULL,

    CONSTRAINT feed_items_priority_check CHECK (priority IN ('P1', 'P2', 'P3', 'ignore')),
    CONSTRAINT feed_items_confidence_check CHECK (confidence IN ('high', 'medium', 'low')),
    CONSTRAINT feed_items_exploitation_check CHECK (exploitation IN ('confirmed', 'reported', 'none')),
    CONSTRAINT feed_items_state_check CHECK (state IN ('queued', 'published', 'ignored', 'suppressed', 'expired'))
);

CREATE INDEX idx_feed_items_queue ON public.feed_items (state, priority) WHERE state = 'queued';
CREATE INDEX idx_feed_items_cves ON public.feed_items USING gin (cves);
CREATE INDEX idx_feed_items_published ON public.feed_items (last_published_at DESC) WHERE last_published_at IS NOT NULL;

-- As in migrations 001 and 002: Supabase's Data API roles get no rows, the owner keeps access.
ALTER TABLE public.feed_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feed_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feed_items ENABLE ROW LEVEL SECURITY;

COMMIT;
