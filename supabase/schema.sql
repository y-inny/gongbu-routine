begin;
create table if not exists public.study_state (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null,
  revision bigint not null default 1,
  updated_at timestamptz not null default now()
);
alter table public.study_state enable row level security;
revoke all on public.study_state from anon;
grant select, insert, update on public.study_state to authenticated;
drop policy if exists own_state_select on public.study_state;
create policy own_state_select on public.study_state for select to authenticated using ((select auth.uid()) = user_id);
drop policy if exists own_state_insert on public.study_state;
create policy own_state_insert on public.study_state for insert to authenticated with check ((select auth.uid()) = user_id and revision = 1);
drop policy if exists own_state_update on public.study_state;
create policy own_state_update on public.study_state for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create table if not exists public.study_backups (
  user_id uuid not null references auth.users(id) on delete cascade,
  backup_day date not null,
  data jsonb not null,
  created_at timestamptz not null default now(),
  primary key(user_id, backup_day)
);
alter table public.study_backups enable row level security;
revoke all on public.study_backups from anon, authenticated;
grant select on public.study_backups to authenticated;
drop policy if exists own_backup_select on public.study_backups;
create policy own_backup_select on public.study_backups for select to authenticated using ((select auth.uid()) = user_id);
create or replace function public.protect_study_revision() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.user_id <> old.user_id or new.revision <> old.revision + 1 then
    raise exception 'Invalid study revision';
  end if;
  insert into public.study_backups(user_id, backup_day, data)
  values(old.user_id, (now() at time zone 'Asia/Seoul')::date, old.data)
  on conflict do nothing;
  new.updated_at = now();
  return new;
end;
$$;
revoke all on function public.protect_study_revision() from public;
drop trigger if exists protect_study_revision on public.study_state;
create trigger protect_study_revision before update on public.study_state for each row execute function public.protect_study_revision();
commit;
