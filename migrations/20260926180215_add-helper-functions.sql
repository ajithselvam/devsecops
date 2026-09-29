-- Helper functions the SDK query builder cannot express.

-- Idempotently provisions the caller's profile row. SECURITY DEFINER because
-- the caller cannot satisfy the profiles INSERT path on its own (there is
-- deliberately no INSERT policy).
CREATE OR REPLACE FUNCTION public.ensure_profile()
RETURNS public.profiles
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  caller uuid := auth.uid();
  result public.profiles;
BEGIN
  IF caller IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  INSERT INTO public.profiles (id, name, avatar_url)
  VALUES (
    caller,
    COALESCE((SELECT u.profile ->> 'name' FROM auth.users u WHERE u.id = caller), ''),
    (SELECT u.profile ->> 'avatar_url' FROM auth.users u WHERE u.id = caller)
  )
  ON CONFLICT (id) DO NOTHING;

  SELECT p.* INTO result FROM public.profiles p WHERE p.id = caller;
  RETURN result;
END;
$$;

REVOKE ALL ON FUNCTION public.ensure_profile() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ensure_profile() TO authenticated;

-- Aggregates used by the stats endpoints. Server-side only.
CREATE OR REPLACE FUNCTION public.scan_stats(p_user_id uuid)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT jsonb_build_object(
    'total', (SELECT count(*) FROM public.scans WHERE user_id = p_user_id),
    'by_type', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('type', type, 'count', cnt) ORDER BY type)
      FROM (SELECT type, count(*) AS cnt
            FROM public.scans WHERE user_id = p_user_id GROUP BY type) t
    ), '[]'::jsonb),
    'by_status', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('status', status, 'count', cnt) ORDER BY status)
      FROM (SELECT status, count(*) AS cnt
            FROM public.scans WHERE user_id = p_user_id GROUP BY status) t
    ), '[]'::jsonb)
  );
$$;

CREATE OR REPLACE FUNCTION public.job_stats(p_user_id uuid)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT jsonb_build_object(
    'total', (SELECT count(*) FROM public.jobs WHERE user_id = p_user_id),
    'running', (SELECT count(*) FROM public.jobs
                WHERE user_id = p_user_id
                  AND status IN ('queued', 'running', 'analyzing', 'fixing')),
    'by_status', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('status', status, 'count', cnt) ORDER BY status)
      FROM (SELECT status, count(*) AS cnt
            FROM public.jobs WHERE user_id = p_user_id GROUP BY status) t
    ), '[]'::jsonb),
    'by_type', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('type', type, 'count', cnt) ORDER BY type)
      FROM (SELECT type, count(*) AS cnt
            FROM public.jobs WHERE user_id = p_user_id GROUP BY type) t
    ), '[]'::jsonb)
  );
$$;

CREATE OR REPLACE FUNCTION public.log_services(p_log_file_id uuid)
RETURNS text[]
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT COALESCE(array_agg(DISTINCT service), '{}'::text[])
  FROM public.log_entries
  WHERE log_file_id = p_log_file_id AND service IS NOT NULL;
$$;

CREATE OR REPLACE FUNCTION public.scan_severity_counts(p_user_id uuid)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT jsonb_build_object(
    'scans', (SELECT count(*) FROM public.scans WHERE user_id = p_user_id),
    'findings', (SELECT count(*) FROM public.findings WHERE user_id = p_user_id),
    'critical', (SELECT count(*) FROM public.findings WHERE user_id = p_user_id AND severity = 'critical'),
    'high', (SELECT count(*) FROM public.findings WHERE user_id = p_user_id AND severity = 'high'),
    'medium', (SELECT count(*) FROM public.findings WHERE user_id = p_user_id AND severity = 'medium'),
    'low', (SELECT count(*) FROM public.findings WHERE user_id = p_user_id AND severity = 'low'),
    'info', (SELECT count(*) FROM public.findings WHERE user_id = p_user_id AND severity = 'info')
  );
$$;

REVOKE ALL ON FUNCTION public.scan_stats(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.job_stats(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.log_services(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.scan_severity_counts(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.scan_stats(uuid) TO project_admin;
GRANT EXECUTE ON FUNCTION public.job_stats(uuid) TO project_admin;
GRANT EXECUTE ON FUNCTION public.log_services(uuid) TO project_admin;
GRANT EXECUTE ON FUNCTION public.scan_severity_counts(uuid) TO project_admin;
