-- Evidence metadata only; raw image bytes are not stored here.
CREATE TABLE IF NOT EXISTS public.evidence_vault (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id uuid NOT NULL,
    image_hash text NOT NULL,
    timestamp timestamptz NOT NULL DEFAULT now(),
    matched_urls jsonb NOT NULL DEFAULT '[]'::jsonb,
    status text NOT NULL DEFAULT 'pending'
);

ALTER TABLE public.evidence_vault ENABLE ROW LEVEL SECURITY;

-- No client policies are granted: access is restricted to trusted backend
-- connections (such as the Supabase service role, which bypasses RLS).
