-- Initial scaffold. The platform schema is created by the follow-up
-- migrations (create-core-tables, add-schema-triggers, add-row-level-security,
-- add-grants-and-helpers). Kept for migration-history continuity.

CREATE TABLE public.t1 (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid()
);
