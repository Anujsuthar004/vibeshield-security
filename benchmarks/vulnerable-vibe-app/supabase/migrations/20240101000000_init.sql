-- profiles: RLS on, but policies are wide open
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  plan text default 'free'
);
alter table public.profiles enable row level security;

-- anyone with the anon key can read every email
create policy "Profiles are public" on public.profiles
  for select using (true);

-- anyone can upgrade anyone to the paid plan
create policy "Anyone can update profiles" on public.profiles
  for update using (true);

-- invoices: created here, never gets RLS in any migration
create table if not exists "public"."invoices" (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  amount_cents int not null
);

-- notes: RLS enabled in the next migration (must not be flagged)
create table notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid(),
  body text
);

-- signed-in users can delete any note, not just their own
create policy "Signed-in users can delete notes" on notes
  for delete to authenticated using (user_id is not null);

-- view in the exposed schema without security_invoker bypasses RLS on profiles
create view public.leaderboard as
  select email, plan from public.profiles;

-- security definer without a fixed search_path
create or replace function public.grant_pro(target uuid)
returns void
language plpgsql
security definer
as $$
begin
  update profiles set plan = 'pro' where id = target;
end;
$$;
