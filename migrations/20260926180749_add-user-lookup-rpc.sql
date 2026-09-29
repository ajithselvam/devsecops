-- auth.users is not exposed over the data API (authenticated has no SELECT on
-- it), so the server needs an RPC to read the email alongside a profile row.

CREATE OR REPLACE FUNCTION public.get_user(p_user_id uuid)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT jsonb_build_object(
    'id', u.id,
    'email', u.email,
    'name', COALESCE(p.name, u.profile ->> 'name', ''),
    'avatarUrl', p.avatar_url,
    'role', COALESCE(p.role, 'engineer'),
    'theme', COALESCE(p.theme, 'system'),
    'sidebarCollapsed', COALESCE(p.sidebar_collapsed, false),
    'language', COALESCE(p.language, 'en'),
    'emailNotifications', COALESCE(p.email_notifications, true),
    'inAppNotifications', COALESCE(p.in_app_notifications, true),
    'notifyScanComplete', COALESCE(p.notify_scan_complete, true),
    'notifyScanFailed', COALESCE(p.notify_scan_failed, true),
    'notifyVulnFound', COALESCE(p.notify_vuln_found, true),
    'notifyJobChange', COALESCE(p.notify_job_change, true),
    'lastLoginAt', p.last_login_at,
    'createdAt', u.created_at,
    'updatedAt', u.updated_at
  )
  FROM auth.users u
  LEFT JOIN public.profiles p ON p.id = u.id
  WHERE u.id = p_user_id;
$$;

CREATE OR REPLACE FUNCTION public.get_user_by_email(p_email text)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT public.get_user(u.id)
  FROM auth.users u
  WHERE lower(u.email) = lower(p_email);
$$;

CREATE OR REPLACE FUNCTION public.touch_last_login(p_user_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  UPDATE public.profiles SET last_login_at = now() WHERE id = p_user_id;
$$;

REVOKE ALL ON FUNCTION public.get_user(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_user_by_email(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.touch_last_login(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_user(uuid) TO project_admin;
GRANT EXECUTE ON FUNCTION public.get_user_by_email(text) TO project_admin;
GRANT EXECUTE ON FUNCTION public.touch_last_login(uuid) TO project_admin;
