--
-- PostgreSQL database dump
--

\restrict aj6IgHAycWf2GdXcNNlZ7j9QIqQJXGfguIT9dWCccKBJH7XU8wJlWNrCrjQ4Q2W

-- Dumped from database version 17.7
-- Dumped by pg_dump version 17.7

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    investigation_id uuid NOT NULL,
    source text NOT NULL,
    source_type text NOT NULL,
    title text NOT NULL,
    url text NOT NULL,
    confidence text NOT NULL,
    retrieved_at timestamp with time zone NOT NULL,
    raw_payload jsonb NOT NULL,
    source_references jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_evidence_id text,
    CONSTRAINT evidence_confidence_check CHECK ((confidence = ANY (ARRAY['high'::text, 'medium'::text, 'low'::text]))),
    CONSTRAINT evidence_source_type_check CHECK ((source_type = ANY (ARRAY['primary'::text, 'vendor'::text, 'community'::text])))
);


--
-- Name: facts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.facts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    investigation_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    claim text NOT NULL,
    field text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_fact_id text
);


--
-- Name: inferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.inferences (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    investigation_id uuid NOT NULL,
    claim text NOT NULL,
    supporting_fact_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_inference_id text
);


--
-- Name: investigations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    target text NOT NULL,
    target_type text NOT NULL,
    investigation_type text NOT NULL,
    status text NOT NULL,
    summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    provider_results jsonb DEFAULT '[]'::jsonb NOT NULL,
    limitations jsonb DEFAULT '[]'::jsonb NOT NULL,
    analyst_guidance jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT investigations_status_check CHECK ((status = ANY (ARRAY['confirmed'::text, 'partial'::text, 'not-found'::text, 'failed'::text])))
);


--
-- Name: evidence evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (id);


--
-- Name: facts facts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.facts
    ADD CONSTRAINT facts_pkey PRIMARY KEY (id);


--
-- Name: inferences inferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inferences
    ADD CONSTRAINT inferences_pkey PRIMARY KEY (id);


--
-- Name: investigations investigations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigations
    ADD CONSTRAINT investigations_pkey PRIMARY KEY (id);


--
-- Name: idx_evidence_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_investigation ON public.evidence USING btree (investigation_id);


--
-- Name: idx_evidence_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_source ON public.evidence USING btree (source);


--
-- Name: idx_facts_evidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_facts_evidence ON public.facts USING btree (evidence_id);


--
-- Name: idx_facts_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_facts_investigation ON public.facts USING btree (investigation_id);


--
-- Name: idx_inferences_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inferences_investigation ON public.inferences USING btree (investigation_id);


--
-- Name: idx_investigations_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_created_at ON public.investigations USING btree (created_at);


--
-- Name: idx_investigations_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_target ON public.investigations USING btree (target);


--
-- Name: evidence evidence_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: facts facts_evidence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.facts
    ADD CONSTRAINT facts_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES public.evidence(id) ON DELETE RESTRICT;


--
-- Name: facts facts_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.facts
    ADD CONSTRAINT facts_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: inferences inferences_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inferences
    ADD CONSTRAINT inferences_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict aj6IgHAycWf2GdXcNNlZ7j9QIqQJXGfguIT9dWCccKBJH7XU8wJlWNrCrjQ4Q2W

