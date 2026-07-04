-- RLS boundary suite for Atomic CRM.
-- Enable pgTAP on THIS ephemeral DB only. Do NOT move this into a migration:
-- that would deploy pgtap to prod and add a 25th migration, breaking the
-- "24 migrations == prod boundary" parity this suite relies on.
create extension if not exists pgtap with schema extensions;

begin;
select plan(1);

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

-- Smoke assertion, replaced by real arms in later tasks.
select ok(true, 'fixtures loaded: pgtap harness is live');

select * from finish();
rollback;
