-- Run this once in the Supabase SQL Editor (Project -> SQL Editor -> New query -> Run).
-- Sets up RSVP storage, a 100-seat cap per side, and per-guest invitation codes.

create extension if not exists pgcrypto;

create table if not exists side_counts (
  side text primary key check (side in ('groom','bride')),
  capacity integer not null,
  used integer not null default 0 check (used >= 0)
);

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
  code text unique
);

alter table side_counts enable row level security;
alter table rsvps enable row level security;
-- Deliberately no policies for anon on either table: the site never talks to
-- them directly, only through submit_rsvp()/side_status below.

create or replace view side_status as
  select side, (used >= capacity) as is_full
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
create or replace function submit_rsvp(
  p_name text,
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
  if p_side not in ('groom','bride') then
    return jsonb_build_object('ok', false, 'error', 'invalid_side');
  end if;

  p_name := trim(coalesce(p_name, ''));
  if length(p_name) = 0 then
    return jsonb_build_object('ok', false, 'error', 'invalid_name');
  end if;

  p_companions := greatest(coalesce(p_companions, 0), 0);

  if not p_attending then
    insert into rsvps (guest_name, side, attending, companions, notes)
    values (p_name, p_side, false, p_companions, p_notes);
    return jsonb_build_object('ok', true, 'attending', false);
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
  insert into rsvps (guest_name, side, attending, companions, notes, code)
  values (p_name, p_side, true, p_companions, p_notes, v_code);

  return jsonb_build_object('ok', true, 'attending', true, 'code', v_code);
exception when others then
  return jsonb_build_object('ok', false, 'error', 'server_error');
end;
$$;

grant execute on function submit_rsvp(text, text, boolean, integer, text) to anon;
