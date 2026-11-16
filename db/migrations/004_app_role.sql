-- Apply after 003_threat_feed.sql. Safe to paste into the Supabase SQL editor; safe to run twice.
--
-- A least-privilege role for the plugin. It can read and write the plugin's
-- own nine tables and nothing else: no other schemas (such as Supabase's auth),
-- no DDL, no role management, and no row-level-security bypass. Its password
-- is set separately (ALTER ROLE ... PASSWORD) so it never appears in this file.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'threatintel_app') THEN
        CREATE ROLE threatintel_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;

-- In case the role existed with wider rights.
ALTER ROLE threatintel_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT USAGE ON SCHEMA public TO threatintel_app;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'investigations', 'evidence', 'facts', 'inferences',
        'watchlist', 'watch_events',
        'feed_state', 'feed_runs', 'feed_items'
    ]
    LOOP
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO threatintel_app', t);

        -- Row-level security stays on for every table. This role gets a policy
        -- on these tables only; Supabase's anon and authenticated roles still get none.
        EXECUTE format('DROP POLICY IF EXISTS threatintel_app_all ON public.%I', t);
        EXECUTE format(
            'CREATE POLICY threatintel_app_all ON public.%I FOR ALL TO threatintel_app USING (true) WITH CHECK (true)',
            t
        );
    END LOOP;
END
$$;

COMMIT;
