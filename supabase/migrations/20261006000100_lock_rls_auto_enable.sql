-- rls_auto_enable() is Supabase's event trigger that turns on RLS for new
-- tables. Event triggers do not need EXECUTE, so nobody should be able to call
-- it through the Data API.
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
