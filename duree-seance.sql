-- Modifier la durée d'une séance terminée (client sur ses séances, coach/gérant/admin sur celles de ses clients).
-- À lancer une fois dans Supabase > SQL Editor (peut être relancé sans risque).
create or replace function public.set_session_duration(p_session uuid, p_seconds integer)
returns integer language plpgsql security definer set search_path = public as $$
declare s public.sessions; v int;
begin
  if auth.uid() is null then raise exception 'non connecte'; end if;
  select * into s from public.sessions where id = p_session;
  if s.id is null then raise exception 'seance introuvable'; end if;
  if not (s.user_id = auth.uid() or coalesce(public.can_manage(s.user_id), false)) then raise exception 'interdit'; end if;
  if s.completed_at is null then raise exception 'seance non terminee'; end if;
  v := greatest(60, least(coalesce(p_seconds, 0), 21600));   -- entre 1 min et 6 h
  -- la protection des séances (sessions_guard) laisse passer cette mise à jour contrôlée
  perform set_config('request.jwt.claims', '', true);
  update public.sessions set declared_seconds = v,
    completed_at = case when source = 'live' then completed_at else least(now(), started_at + make_interval(secs => v)) end
  where id = p_session;
  return v;
end $$;
revoke all on function public.set_session_duration(uuid, integer) from public, anon;
grant execute on function public.set_session_duration(uuid, integer) to authenticated;
notify pgrst, 'reload schema';
