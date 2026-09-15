-- Run this once in the Supabase SQL Editor (Project -> SQL Editor -> New query -> Run).
-- Sets up RSVP storage, a 100-seat cap per side, and per-guest invitation codes.

create extension if not exists pgcrypto;

create table if not exists side_counts (
  side text primary key check (side in ('groom','bride')),
  capacity integer not null,
  used integer not null default 0 check (used >= 0),
  enabled boolean not null default true
);

alter table side_counts add column if not exists enabled boolean not null default true;

insert into side_counts (side, capacity, used) values
  ('groom', 100, 0),
  ('bride', 100, 0)
on conflict (side) do nothing;

create table if not exists rsvps (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  guest_name text not null,
  side text not null check (side in ('groom','bride')),
  attending boolean not null,
  companions integer not null default 0 check (companions >= 0),
  notes text,
  code text unique,
  phone text,
  capacity_rejected boolean not null default false
);

alter table rsvps add column if not exists phone text;
alter table rsvps add column if not exists capacity_rejected boolean not null default false;

alter table side_counts enable row level security;
alter table rsvps enable row level security;
-- Deliberately no policies for anon on either table: the site never talks to
-- them directly, only through submit_rsvp()/side_status below.

create or replace view side_status as
  select side, (used >= capacity) as is_full, enabled
  from side_counts;

grant select on side_status to anon;

create or replace function generate_invite_code() returns text
language plpgsql as $$
declare
  chars text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  v_code text;
  taken boolean;
begin
  loop
    v_code := '';
    for i in 1..6 loop
      v_code := v_code || substr(chars, (floor(random() * length(chars)) + 1)::int, 1);
    end loop;
    select exists(select 1 from rsvps where rsvps.code = v_code) into taken;
    exit when not taken;
  end loop;
  return v_code;
end;
$$;

revoke all on function generate_invite_code() from public;

-- Single entry point the page calls. security definer + no anon grants on the
-- tables above means capacity can't be bypassed or tampered with from the client.
drop function if exists submit_rsvp(text, text, boolean, integer, text);

create or replace function submit_rsvp(
  p_name text,
  p_side text,
  p_attending boolean,
  p_companions integer,
  p_notes text,
  p_phone text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_party_size integer;
  v_code text;
  v_updated integer;
  v_enabled boolean;
  v_existing_code text;
begin
  if p_side not in ('groom','bride') then
    return jsonb_build_object('ok', false, 'error', 'invalid_side');
  end if;

  select enabled into v_enabled from side_counts where side = p_side;
  if not coalesce(v_enabled, true) then
    return jsonb_build_object('ok', false, 'error', 'side_disabled');
  end if;

  p_phone := trim(coalesce(p_phone, ''));
  if length(p_phone) = 0 then
    return jsonb_build_object('ok', false, 'error', 'invalid_phone');
  end if;

  -- Returning guest: same phone already has a confirmed spot on this side.
  -- Hand back their existing code/location instead of registering again.
  select code into v_existing_code
    from rsvps
    where side = p_side and phone = p_phone and attending = true
    order by created_at desc
    limit 1;

  if v_existing_code is not null then
    return jsonb_build_object('ok', true, 'already_registered', true, 'attending', true, 'code', v_existing_code);
  end if;

  p_name := trim(coalesce(p_name, ''));
  if length(p_name) = 0 then
    return jsonb_build_object('ok', false, 'error', 'invalid_name');
  end if;

  p_companions := greatest(coalesce(p_companions, 0), 0);

  if not p_attending then
    insert into rsvps (guest_name, side, attending, companions, notes, phone)
    values (p_name, p_side, false, p_companions, p_notes, p_phone);
    return jsonb_build_object('ok', true, 'attending', false);
  end if;

  v_party_size := 1 + p_companions;

  update side_counts
    set used = used + v_party_size
    where side = p_side and used + v_party_size <= capacity;
  get diagnostics v_updated = row_count;

  if v_updated = 0 then
    insert into rsvps (guest_name, side, attending, companions, notes, phone, capacity_rejected)
    values (p_name, p_side, false, p_companions, p_notes, p_phone, true);
    return jsonb_build_object('ok', false, 'error', 'side_full');
  end if;

  v_code := generate_invite_code();
  insert into rsvps (guest_name, side, attending, companions, notes, code, phone)
  values (p_name, p_side, true, p_companions, p_notes, v_code, p_phone);

  return jsonb_build_object('ok', true, 'attending', true, 'code', v_code);
exception when others then
  return jsonb_build_object('ok', false, 'error', 'server_error');
end;
$$;

grant execute on function submit_rsvp(text, text, boolean, integer, text, text) to anon;

-- Admin access for admin.html. Lets the signed-in Supabase Auth users listed
-- below read the guest list; RLS still blocks everyone else (including anon)
-- from reading rsvps directly. Create each user yourself first: Supabase
-- dashboard -> Authentication -> Users -> Add user. Add/remove emails from
-- the list below (here and in every admin_* function) to change who counts
-- as an admin.
--
-- RLS policies only filter rows; the authenticated role still needs the
-- base table-level privilege or every query 42501s regardless of policy.
grant select on rsvps to authenticated;
grant select on side_counts to authenticated;

drop policy if exists "admin can read rsvps" on rsvps;
create policy "admin can read rsvps" on rsvps
  for select to authenticated
  using (coalesce(auth.jwt() ->> 'email', '') in ('qwas30000@gmail.com', 'md.ad.alnasser@gmail.com'));

drop policy if exists "admin can read side_counts" on side_counts;
create policy "admin can read side_counts" on side_counts
  for select to authenticated
  using (coalesce(auth.jwt() ->> 'email', '') in ('qwas30000@gmail.com', 'md.ad.alnasser@gmail.com'));

create or replace function admin_set_capacity(p_side text, p_new_capacity integer)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(auth.jwt() ->> 'email', '') not in ('qwas30000@gmail.com', 'md.ad.alnasser@gmail.com') then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_side not in ('groom','bride') then
    return jsonb_build_object('ok', false, 'error', 'invalid_side');
  end if;
  if p_new_capacity is null or p_new_capacity < 0 then
    return jsonb_build_object('ok', false, 'error', 'invalid_capacity');
  end if;

  update side_counts set capacity = p_new_capacity where side = p_side;
  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function admin_set_capacity(text, integer) to authenticated;

create or replace function admin_set_enabled(p_side text, p_enabled boolean)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(auth.jwt() ->> 'email', '') not in ('qwas30000@gmail.com', 'md.ad.alnasser@gmail.com') then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_side not in ('groom','bride') then
    return jsonb_build_object('ok', false, 'error', 'invalid_side');
  end if;
  if p_enabled is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_value');
  end if;

  update side_counts set enabled = p_enabled where side = p_side;
  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function admin_set_enabled(text, boolean) to authenticated;

-- Admin CRUD on the guest list (admin.html). Each function re-checks the
-- admin email itself, same as the functions above, and keeps side_counts.used
-- consistent with whatever attending/companions/side end up being true.
create or replace function admin_add_rsvp(
  p_name text,
  p_phone text,
  p_side text,
  p_attending boolean,
  p_companions integer,
  p_notes text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_party_size integer;
  v_code text;
  v_updated integer;
begin
  if coalesce(auth.jwt() ->> 'email', '') not in ('qwas30000@gmail.com', 'md.ad.alnasser@gmail.com') then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_side not in ('groom','bride') then
    return jsonb_build_object('ok', false, 'error', 'invalid_side');
  end if;

  p_name := trim(coalesce(p_name, ''));
  if length(p_name) = 0 then
    return jsonb_build_object('ok', false, 'error', 'invalid_name');
  end if;

  p_companions := greatest(coalesce(p_companions, 0), 0);
  p_phone := nullif(trim(coalesce(p_phone, '')), '');

  if not p_attending then
    insert into rsvps (guest_name, side, attending, companions, notes, phone)
    values (p_name, p_side, false, p_companions, p_notes, p_phone);
    return jsonb_build_object('ok', true);
  end if;

  v_party_size := 1 + p_companions;
  update side_counts
    set used = used + v_party_size
    where side = p_side and used + v_party_size <= capacity;
  get diagnostics v_updated = row_count;
  if v_updated = 0 then
    return jsonb_build_object('ok', false, 'error', 'side_full');
  end if;

  v_code := generate_invite_code();
  insert into rsvps (guest_name, side, attending, companions, notes, code, phone)
  values (p_name, p_side, true, p_companions, p_notes, v_code, p_phone);

  return jsonb_build_object('ok', true, 'code', v_code);
end;
$$;

grant execute on function admin_add_rsvp(text, text, text, boolean, integer, text) to authenticated;

create or replace function admin_update_rsvp(
  p_id uuid,
  p_name text,
  p_phone text,
  p_side text,
  p_attending boolean,
  p_companions integer,
  p_notes text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_old rsvps%rowtype;
  v_new_party integer;
  v_updated integer;
begin
  if coalesce(auth.jwt() ->> 'email', '') not in ('qwas30000@gmail.com', 'md.ad.alnasser@gmail.com') then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_side not in ('groom','bride') then
    return jsonb_build_object('ok', false, 'error', 'invalid_side');
  end if;

  p_name := trim(coalesce(p_name, ''));
  if length(p_name) = 0 then
    return jsonb_build_object('ok', false, 'error', 'invalid_name');
  end if;

  p_companions := greatest(coalesce(p_companions, 0), 0);
  p_phone := nullif(trim(coalesce(p_phone, '')), '');

  select * into v_old from rsvps where id = p_id;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;

  if v_old.attending then
    update side_counts set used = greatest(used - (1 + v_old.companions), 0) where side = v_old.side;
  end if;

  if p_attending then
    v_new_party := 1 + p_companions;
    update side_counts
      set used = used + v_new_party
      where side = p_side and used + v_new_party <= capacity;
    get diagnostics v_updated = row_count;
    if v_updated = 0 then
      if v_old.attending then
        update side_counts set used = used + (1 + v_old.companions) where side = v_old.side;
      end if;
      return jsonb_build_object('ok', false, 'error', 'side_full');
    end if;
  end if;

  update rsvps set
    guest_name = p_name,
    phone = p_phone,
    side = p_side,
    attending = p_attending,
    companions = p_companions,
    notes = p_notes,
    code = case when p_attending and code is null then generate_invite_code() else code end
  where id = p_id;

  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function admin_update_rsvp(uuid, text, text, text, boolean, integer, text) to authenticated;

create or replace function admin_delete_rsvp(p_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_old rsvps%rowtype;
begin
  if coalesce(auth.jwt() ->> 'email', '') not in ('qwas30000@gmail.com', 'md.ad.alnasser@gmail.com') then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;

  select * into v_old from rsvps where id = p_id;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;

  if v_old.attending then
    update side_counts set used = greatest(used - (1 + v_old.companions), 0) where side = v_old.side;
  end if;

  delete from rsvps where id = p_id;
  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function admin_delete_rsvp(uuid) to authenticated;
