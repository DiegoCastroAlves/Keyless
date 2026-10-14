-- Keeps the project from being paused: the Free plan pauses projects with
-- too little database activity over a week. An outside scheduler (cron-job.org)
-- calls GET /rest/v1/rpc/keepalive with the publishable key a few times a day.
--
-- It reads one row of a real table, as an app request would, and answers
-- only true: nothing about the accounts. Anyone with the publishable key can
-- call it, which costs one indexed read.

create function public.keepalive() returns boolean
language plpgsql stable security definer set search_path = '' as $$
begin
  perform 1 from public.profiles limit 1;
  return true;
end;
$$;
revoke all on function public.keepalive() from public;
grant execute on function public.keepalive() to anon, authenticated;
