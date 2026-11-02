-- Apply after db/schema.sql. Safe to paste into the Supabase SQL editor.
-- Runs in one transaction: if existing rows violate a new rule, nothing changes.

BEGIN;

-- Replay and tamper detection
ALTER TABLE public.investigations ADD COLUMN engine_version text;
ALTER TABLE public.evidence ADD COLUMN content_sha256 text;

-- A fact may only cite evidence from its own investigation
ALTER TABLE public.evidence
    ADD CONSTRAINT evidence_id_investigation_key UNIQUE (id, investigation_id);

ALTER TABLE public.facts DROP CONSTRAINT facts_evidence_id_fkey;

ALTER TABLE public.facts
    ADD CONSTRAINT facts_evidence_same_investigation_fkey
    FOREIGN KEY (evidence_id, investigation_id)
    REFERENCES public.evidence (id, investigation_id)
    ON DELETE CASCADE;

-- Source ids are what inferences and replay resolve against
ALTER TABLE public.evidence
    ADD CONSTRAINT evidence_source_id_key UNIQUE (investigation_id, source_evidence_id);

ALTER TABLE public.facts
    ADD CONSTRAINT facts_source_id_key UNIQUE (investigation_id, source_fact_id);

ALTER TABLE public.inferences
    ADD CONSTRAINT inferences_source_id_key UNIQUE (investigation_id, source_inference_id);

-- Investigations are historical records: rows can be deleted, never rewritten
CREATE FUNCTION public.reject_investigation_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER investigations_append_only BEFORE UPDATE ON public.investigations
    FOR EACH ROW EXECUTE FUNCTION public.reject_investigation_update();

CREATE TRIGGER evidence_append_only BEFORE UPDATE ON public.evidence
    FOR EACH ROW EXECUTE FUNCTION public.reject_investigation_update();

CREATE TRIGGER facts_append_only BEFORE UPDATE ON public.facts
    FOR EACH ROW EXECUTE FUNCTION public.reject_investigation_update();

CREATE TRIGGER inferences_append_only BEFORE UPDATE ON public.inferences
    FOR EACH ROW EXECUTE FUNCTION public.reject_investigation_update();

-- Supabase's Data API reads the public schema using the anon and authenticated
-- roles. With RLS on and no policies, those roles get no rows, while the table
-- owner the plugin connects as keeps access.
ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inferences ENABLE ROW LEVEL SECURITY;

COMMIT;
