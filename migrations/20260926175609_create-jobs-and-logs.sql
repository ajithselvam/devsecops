-- jobs
CREATE TABLE public.jobs (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  type          text NOT NULL,
  status        text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'analyzing', 'fixing', 'completed', 'failed', 'cancelled')),
  progress      integer NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  current_step  text NOT NULL DEFAULT '',
  total_steps   integer NOT NULL DEFAULT 1,
  input         jsonb NOT NULL DEFAULT '{}'::jsonb,
  output        jsonb,
  error         text,
  scan_id       uuid UNIQUE,
  started_at    timestamptz,
  completed_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_jobs_user_created ON public.jobs(user_id, created_at DESC);
CREATE INDEX idx_jobs_status ON public.jobs(status);

-- log_files / log_entries
CREATE TABLE public.log_files (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  name        text NOT NULL,
  size        bigint NOT NULL DEFAULT 0,
  line_count  integer NOT NULL DEFAULT 0,
  format      text NOT NULL DEFAULT 'text' CHECK (format IN ('json', 'text', 'syslog', 'nginx', 'apache', 'custom')),
  indexed     boolean NOT NULL DEFAULT false,
  storage_key text,
  storage_url text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_log_files_user_created ON public.log_files(user_id, created_at DESC);

CREATE TABLE public.log_entries (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  log_file_id uuid NOT NULL REFERENCES public.log_files(id) ON DELETE CASCADE,
  timestamp   timestamptz NOT NULL,
  level       text NOT NULL CHECK (level IN ('debug', 'info', 'warn', 'error', 'fatal', 'trace')),
  service     text,
  message     text NOT NULL,
  raw         text NOT NULL DEFAULT '',
  fields      jsonb NOT NULL DEFAULT '{}'::jsonb,
  indexed     boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_log_entries_file_timestamp ON public.log_entries(log_file_id, timestamp DESC);
CREATE INDEX idx_log_entries_file_level ON public.log_entries(log_file_id, level);
CREATE INDEX idx_log_entries_file_service ON public.log_entries(log_file_id, service);
