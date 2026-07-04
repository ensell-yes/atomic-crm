-- RLS boundary suite for Atomic CRM.
-- Enable pgTAP on THIS ephemeral DB only. Do NOT move this into a migration:
-- that would deploy pgtap to prod and add a 25th migration, breaking the
-- "24 migrations == prod boundary" parity this suite relies on.
create extension if not exists pgtap with schema extensions;

begin;
select plan(14);

create function pg_temp.visible_count(query text)
returns int
language plpgsql
as $$
declare
  row_count int;
begin
  execute query into row_count;
  return row_count;
exception
  when insufficient_privilege then
    return -1;
end;
$$;

-- Fixtures run as the superuser `supabase test db` connects as.
-- Seed identities through auth.users. The on_auth_user_created trigger
-- (handle_new_user) auto-creates the matching public.sales row and copies
-- raw_user_meta_data->>'first_name'/'last_name' into NOT NULL columns, so both
-- keys AND a non-null email are required or the trigger throws. NEVER insert
-- into public.sales directly here: the trigger already did, and
-- uq__sales__user_id would reject a second row.
insert into auth.users (id, email, raw_user_meta_data)
values ('00000000-0000-0000-0000-0000000000a1', 'admin@test.example',
        jsonb_build_object('first_name', 'Admin', 'last_name', 'User'));

insert into auth.users (id, email, raw_user_meta_data)
values ('00000000-0000-0000-0000-0000000000b2', 'member@test.example',
        jsonb_build_object('first_name', 'Member', 'last_name', 'User'));

-- Make admin/non-admin deterministic instead of depending on handle_new_user's
-- "first sales row is admin" heuristic (which assumes an empty sales table).
update public.sales set administrator = true  where user_id = '00000000-0000-0000-0000-0000000000a1';
update public.sales set administrator = false where user_id = '00000000-0000-0000-0000-0000000000b2';

-- Configuration singleton (id=1 is enforced by a CHECK constraint) so the
-- admin-only UPDATE arm has a row to act on.
insert into public.configuration (id, config) values (1, '{}'::jsonb)
  on conflict (id) do nothing;

-- One CRM row each for the anon-sees-zero and shared-model-positive arms.
insert into public.contacts (first_name, last_name) values ('Seed', 'Contact');
insert into public.deals (name, stage) values ('Seed Deal', 'opportunity');

-- Arm 1: anon denial.
-- The migration-built stack currently denies anon SELECT at the privilege layer;
-- if future grants expose the tables, the no-anon-policy RLS boundary must still
-- return 0 rows. Any positive count means anon can read CRM data.
set local role anon;
set local request.jwt.claims to '{"role":"anon"}';

select cmp_ok(pg_temp.visible_count('select count(*)::int from public.companies'), '<=', 0, 'anon sees 0 companies');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.contacts'), '<=', 0, 'anon sees 0 contacts');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.contact_notes'), '<=', 0, 'anon sees 0 contact_notes');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.deals'), '<=', 0, 'anon sees 0 deals');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.deal_notes'), '<=', 0, 'anon sees 0 deal_notes');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.tasks'), '<=', 0, 'anon sees 0 tasks');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.tags'), '<=', 0, 'anon sees 0 tags');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.sales'), '<=', 0, 'anon sees 0 sales');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.configuration'), '<=', 0, 'anon sees 0 configuration');
select cmp_ok(pg_temp.visible_count('select count(*)::int from public.favicons_excluded_domains'), '<=', 0, 'anon sees 0 favicons_excluded_domains');

select throws_ok(
  $$ insert into public.contacts (first_name, last_name) values ('anon', 'inject') $$,
  '42501',
  null,
  'anon INSERT into contacts is denied by RLS (42501)');

reset role;

-- Arm 2: privilege escalation blocked.
-- sales has ONLY a SELECT policy, so UPDATE/DELETE match 0 rows.
set local role authenticated;
set local request.jwt.claims to '{"sub":"00000000-0000-0000-0000-0000000000b2","role":"authenticated"}';

select is(
  pg_temp.visible_count($$
    with u as (
      update public.sales set administrator = true
      where user_id = '00000000-0000-0000-0000-0000000000b2' returning 1)
    select count(*)::int from u
  $$),
  0,
  'non-admin UPDATE sales.administrator affects 0 rows');

select is(
  pg_temp.visible_count($$
    with d as (
      delete from public.sales
      where user_id = '00000000-0000-0000-0000-0000000000a1' returning 1)
    select count(*)::int from d
  $$),
  0,
  'non-admin DELETE sales affects 0 rows');

reset role;

-- Re-read as superuser: the escalation attempt changed nothing.
select is(
  (select administrator from public.sales where user_id = '00000000-0000-0000-0000-0000000000b2'),
  false,
  'non-admin administrator flag remains false after escalation attempt');

select * from finish();
rollback;
