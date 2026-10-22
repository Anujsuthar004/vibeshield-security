-- Correct patterns. Nothing in this file should produce a finding.
alter table if exists public.notes enable row level security;

create policy "Users read own notes" on public.notes
  for select to authenticated using ((select auth.uid()) = user_id);

create policy "Users insert own notes" on public.notes
  for insert to authenticated with check (auth.uid() = user_id);

create view public.my_notes with (security_invoker = true) as
  select id, body from public.notes;

create or replace function public.note_count()
returns bigint
language sql
security definer
set search_path = ''
as $$ select count(*) from public.notes where user_id = auth.uid(); $$;
