-- Give every InsForge auth user a public.profiles row the moment they are
-- created, so the row exists for browser data-API access too and the API does
-- not have to provision it on every authenticated request.
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  INSERT INTO public.profiles (id, name, avatar_url)
  VALUES (
    NEW.id,
    COALESCE(NEW.profile ->> 'name', NEW.profile ->> 'full_name', NEW.profile ->> 'user_name', ''),
    NEW.profile ->> 'avatar_url'
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.handle_new_auth_user();

-- Backfill any user that predates this trigger.
INSERT INTO public.profiles (id, name, avatar_url)
SELECT
  u.id,
  COALESCE(u.profile ->> 'name', u.profile ->> 'full_name', u.profile ->> 'user_name', ''),
  u.profile ->> 'avatar_url'
FROM auth.users u
ON CONFLICT (id) DO NOTHING;

REVOKE ALL ON FUNCTION public.handle_new_auth_user() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.handle_new_auth_user() TO project_admin;
