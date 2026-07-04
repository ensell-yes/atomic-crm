-- RLS boundary suite for Atomic CRM.
-- Enable pgTAP on THIS ephemeral DB only. Do NOT move this into a migration:
-- that would deploy pgtap to prod and add a 25th migration, breaking the
-- "24 migrations == prod boundary" parity this suite relies on.
create extension if not exists pgtap with schema extensions;

begin;
select plan(21);

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

-- Seed at least one row in every RLS-enabled public table so each anon-denial
-- assertion is load-bearing if a future grant/policy exposes that table.
insert into public.companies (name) values ('Seed Company');
insert into public.contacts (first_name, last_name) values ('Seed', 'Contact');
insert into public.contact_notes (contact_id, text)
values ((select id from public.contacts where first_name = 'Seed' and last_name = 'Contact'), 'Seed contact note');
insert into public.deals (name, stage) values ('Seed Deal', 'opportunity');
insert into public.deal_notes (deal_id, text)
values ((select id from public.deals where name = 'Seed Deal'), 'Seed deal note');
insert into public.tags (name, color) values ('Seed Tag', '#2563eb');
insert into public.tasks (contact_id, text)
values ((select id from public.contacts where first_name = 'Seed' and last_name = 'Contact'), 'Seed task');

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

-- Arm 3: admin-only configuration writes.
-- UPDATE policy is `using (public.is_admin())`; non-admin cannot write, admin can.
set local role authenticated;
set local request.jwt.claims to '{"sub":"00000000-0000-0000-0000-0000000000b2","role":"authenticated"}';

select is(
  pg_temp.visible_count($$
    with u as (
      update public.configuration set config = '{"touched":true}'::jsonb
      where id = 1 returning 1)
    select count(*)::int from u
  $$),
  0,
  'non-admin UPDATE configuration affects 0 rows');

reset role;

set local role authenticated;
set local request.jwt.claims to '{"sub":"00000000-0000-0000-0000-0000000000a1","role":"authenticated"}';

select is(
  pg_temp.visible_count($$
    with u as (
      update public.configuration set config = '{"touched":true}'::jsonb
      where id = 1 returning 1)
    select count(*)::int from u
  $$),
  1,
  'admin UPDATE configuration affects 1 row');

reset role;

-- Arm 4: shared model intact.
set local role authenticated;
set local request.jwt.claims to '{"sub":"00000000-0000-0000-0000-0000000000b2","role":"authenticated"}';

select cmp_ok(
  (select count(*)::int from public.contacts),
  '>',
  0,
  'authenticated sees shared contacts');

select lives_ok(
  $$ insert into public.contacts (first_name, last_name) values ('New', 'Contact') $$,
  'authenticated can insert contacts (shared workspace write)');

select cmp_ok(
  (select count(*)::int from public.sales),
  '>',
  0,
  'authenticated can read the sales directory');

reset role;

-- Arm 5: live catalog reconciliation.
-- Prove the running stack enforces RLS on exactly the expected public tables and
-- that sales exposes no write policy.
select is(
  (select coalesce(array_agg(c.relname order by c.relname collate "C"), array[]::name[])::text
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r', 'p') and c.relrowsecurity),
  '{companies,configuration,contact_notes,contacts,deal_notes,deals,favicons_excluded_domains,sales,tags,tasks}',
  'exactly 10 expected public tables have RLS enabled');

select is(
  (select count(*)::int from pg_policies
    where schemaname = 'public' and tablename = 'sales' and cmd <> 'SELECT'),
  0,
  'sales exposes no non-SELECT policy (escalation write-surface is closed)');

select * from finish();
rollback;
