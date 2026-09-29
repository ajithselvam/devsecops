-- Storage access control for the log-files and scan-artifacts buckets.
--
-- Both buckets are created with `insforge storage create-bucket <name> --private`.
-- They must stay private: a public bucket serves object GETs with root access,
-- bypassing storage.objects RLS entirely. Note that project_admin cannot write
-- to storage.buckets, so visibility is fixed at create time, not here.
--
-- Access is granted through path-scoped policies: the first key segment is the
-- owning user's id, which the server sets explicitly and so does not depend on
-- uploaded_by being populated by a REST upload.

ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

GRANT USAGE ON SCHEMA storage TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage.objects TO authenticated;

CREATE POLICY storage_objects_path_select ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket IN ('log-files', 'scan-artifacts')
    AND (storage.foldername(key))[1] = (SELECT auth.jwt() ->> 'sub')
  );

CREATE POLICY storage_objects_path_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket IN ('log-files', 'scan-artifacts')
    AND (storage.foldername(key))[1] = (SELECT auth.jwt() ->> 'sub')
  );

CREATE POLICY storage_objects_path_update ON storage.objects
  FOR UPDATE TO authenticated
  USING (
    bucket IN ('log-files', 'scan-artifacts')
    AND (storage.foldername(key))[1] = (SELECT auth.jwt() ->> 'sub')
  )
  WITH CHECK (
    bucket IN ('log-files', 'scan-artifacts')
    AND (storage.foldername(key))[1] = (SELECT auth.jwt() ->> 'sub')
  );

CREATE POLICY storage_objects_path_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket IN ('log-files', 'scan-artifacts')
    AND (storage.foldername(key))[1] = (SELECT auth.jwt() ->> 'sub')
  );
