-- Triggers that keep denormalized ownership columns and updated_at honest.

-- user_id is copied from the parent row so RLS can stay a flat owner check
-- instead of a join back through the parent.
CREATE OR REPLACE FUNCTION public.sync_findings_user_id() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  owner uuid;
BEGIN
  SELECT s.user_id INTO owner FROM public.scans s WHERE s.id = NEW.scan_id;
  IF owner IS NULL THEN
    RAISE EXCEPTION 'scan % does not exist', NEW.scan_id;
  END IF;
  NEW.user_id := owner;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.sync_log_entries_user_id() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  owner uuid;
BEGIN
  SELECT l.user_id INTO owner FROM public.log_files l WHERE l.id = NEW.log_file_id;
  IF owner IS NULL THEN
    RAISE EXCEPTION 'log_file % does not exist', NEW.log_file_id;
  END IF;
  NEW.user_id := owner;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.sync_github_scans_user_id() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  owner uuid;
BEGIN
  SELECT r.user_id INTO owner FROM public.github_repositories r WHERE r.id = NEW.repo_id;
  IF owner IS NULL THEN
    RAISE EXCEPTION 'github_repository % does not exist', NEW.repo_id;
  END IF;
  NEW.user_id := owner;
  RETURN NEW;
END;
$$;

CREATE TRIGGER findings_sync_user_id
  BEFORE INSERT OR UPDATE OF scan_id ON public.findings
  FOR EACH ROW EXECUTE FUNCTION public.sync_findings_user_id();

CREATE TRIGGER log_entries_sync_user_id
  BEFORE INSERT OR UPDATE OF log_file_id ON public.log_entries
  FOR EACH ROW EXECUTE FUNCTION public.sync_log_entries_user_id();

CREATE TRIGGER github_scans_sync_user_id
  BEFORE INSERT OR UPDATE OF repo_id ON public.github_scans
  FOR EACH ROW EXECUTE FUNCTION public.sync_github_scans_user_id();

-- updated_at maintenance
CREATE TRIGGER profiles_updated_at BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
CREATE TRIGGER settings_updated_at BEFORE UPDATE ON public.settings
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
CREATE TRIGGER scans_updated_at BEFORE UPDATE ON public.scans
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
CREATE TRIGGER findings_updated_at BEFORE UPDATE ON public.findings
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
CREATE TRIGGER jobs_updated_at BEFORE UPDATE ON public.jobs
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
CREATE TRIGGER log_files_updated_at BEFORE UPDATE ON public.log_files
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
CREATE TRIGGER github_repositories_updated_at BEFORE UPDATE ON public.github_repositories
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
CREATE TRIGGER notifications_updated_at BEFORE UPDATE ON public.notifications
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
CREATE TRIGGER api_keys_updated_at BEFORE UPDATE ON public.api_keys
  FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
