create extension if not exists pgcrypto;

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text not null,
  created_at timestamptz not null default now()
);

create table public.cash_settings (
  user_id uuid primary key references auth.users (id) on delete cascade,
  initial_balance numeric(12,2) not null default 0 check (initial_balance >= 0),
  updated_at timestamptz not null default now()
);

create table public.sales (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  product_name text not null,
  description text,
  category text,
  quantity integer not null default 1 check (quantity > 0),
  unit_price numeric(12,2) not null check (unit_price >= 0),
  unit_cost numeric(12,2) check (unit_cost is null or unit_cost >= 0),
  payment_method text not null,
  sold_at timestamptz not null default now(),
  notes text,
  status text not null default 'active' check (status in ('active', 'cancelled')),
  created_at timestamptz not null default now()
);

create table public.service_orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  customer_name text,
  customer_phone text,
  device text not null,
  maintenance_type text not null,
  problem text,
  work_done text,
  amount numeric(12,2) not null default 0 check (amount >= 0),
  parts_cost numeric(12,2) check (parts_cost is null or parts_cost >= 0),
  payment_method text,
  received_at timestamptz,
  status text not null default 'received' check (status in ('received', 'analyzing', 'waiting_parts', 'in_progress', 'completed', 'delivered', 'cancelled')),
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, user_id)
);

create table public.service_payments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  service_id uuid not null,
  amount numeric(12,2) not null check (amount > 0),
  payment_method text not null,
  received_at timestamptz not null default now(),
  status text not null default 'active' check (status in ('active', 'cancelled')),
  created_at timestamptz not null default now(),
  constraint service_payments_owner_service_fk foreign key (service_id, user_id)
    references public.service_orders (id, user_id) on delete cascade
);

create table public.withdrawals (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  amount numeric(12,2) not null check (amount > 0),
  reason text not null,
  category text not null,
  withdrawn_at timestamptz not null default now(),
  notes text,
  status text not null default 'active' check (status in ('active', 'cancelled')),
  created_at timestamptz not null default now()
);

create table public.costs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  description text not null,
  category text not null,
  amount numeric(12,2) not null check (amount > 0),
  incurred_at timestamptz not null default now(),
  status text not null default 'active' check (status in ('active', 'cancelled')),
  created_at timestamptz not null default now()
);

create table public.cash_adjustments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  previous_balance numeric(12,2) not null,
  new_balance numeric(12,2) not null check (new_balance >= 0),
  reason text not null,
  created_at timestamptz not null default now()
);

create or replace function public.enforce_service_payment_limit()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  service_amount numeric(12,2);
  already_received numeric(12,2);
begin
  if new.status = 'active' then
    select amount into service_amount
    from public.service_orders
    where id = new.service_id and user_id = new.user_id
    for update;

    if service_amount is null then
      raise exception 'Ordem de serviço não encontrada.';
    end if;

    select coalesce(sum(amount), 0) into already_received
    from public.service_payments
    where service_id = new.service_id
      and user_id = new.user_id
      and status = 'active'
      and id <> new.id;

    if already_received + new.amount > service_amount then
      raise exception 'O recebimento ultrapassa o saldo pendente do serviço.';
    end if;
  end if;
  return new;
end;
$$;

create trigger service_payment_limit
  before insert or update on public.service_payments
  for each row execute procedure public.enforce_service_payment_limit();

create index sales_user_date_idx on public.sales (user_id, sold_at desc);
create index services_user_date_idx on public.service_orders (user_id, created_at desc);
create index service_payments_user_date_idx on public.service_payments (user_id, received_at desc);
create index withdrawals_user_date_idx on public.withdrawals (user_id, withdrawn_at desc);
create index costs_user_date_idx on public.costs (user_id, incurred_at desc);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''));
  insert into public.cash_settings (user_id, initial_balance)
  values (new.id, 0);
  return new;
end;
$$;

alter table public.app_settings
  add column logo_url text,
  add column banner_url text;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to service_role;

create table private.payment_secret_refs (
  singleton boolean primary key default true check (singleton),
  access_token_id uuid,
  webhook_secret_id uuid,
  email_api_key_id uuid,
  email_from text,
  updated_at timestamptz not null default now()
);

insert into private.payment_secret_refs (singleton)
values (true)
on conflict (singleton) do nothing;

alter table private.payment_secret_refs enable row level security;
revoke all on private.payment_secret_refs from public, anon, authenticated;
grant select, insert, update, delete on private.payment_secret_refs to service_role;

create or replace function public.is_app_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from auth.users u
    where u.id = (select auth.uid())
      and lower(u.email) = 'alexandremoderbr@gmail.com'
      and u.email_confirmed_at is not null
  );
$$;

create or replace function public.save_payment_configuration(
  p_access_token text default null,
  p_webhook_secret text default null,
  p_email_api_key text default null,
  p_email_from text default null
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_refs private.payment_secret_refs%rowtype;
  next_access_token_id uuid;
  next_webhook_secret_id uuid;
  next_email_api_key_id uuid;
begin
  if not public.is_app_admin() then
    raise exception 'Acesso restrito ao administrador.';
  end if;

  select * into current_refs
    from private.payment_secret_refs
    where singleton = true
    for update;

  next_access_token_id := current_refs.access_token_id;
  next_webhook_secret_id := current_refs.webhook_secret_id;
  next_email_api_key_id := current_refs.email_api_key_id;

  if nullif(trim(p_access_token), '') is not null then
    next_access_token_id := vault.create_secret(
      trim(p_access_token),
      'flux-mp-access-' || gen_random_uuid()::text,
      'Flux Mercado Pago access token'
    );
  end if;
  if nullif(trim(p_webhook_secret), '') is not null then
    next_webhook_secret_id := vault.create_secret(
      trim(p_webhook_secret),
      'flux-mp-webhook-' || gen_random_uuid()::text,
      'Flux Mercado Pago webhook signing secret'
    );
  end if;
  if nullif(trim(p_email_api_key), '') is not null then
    next_email_api_key_id := vault.create_secret(
      trim(p_email_api_key),
      'flux-email-' || gen_random_uuid()::text,
      'Flux invitation email provider API key'
    );
  end if;

  update private.payment_secret_refs
    set access_token_id = next_access_token_id,
        webhook_secret_id = next_webhook_secret_id,
        email_api_key_id = next_email_api_key_id,
        email_from = coalesce(nullif(trim(p_email_from), ''), email_from),
        updated_at = now()
    where singleton = true;

  if current_refs.access_token_id is distinct from next_access_token_id
      and current_refs.access_token_id is not null then
    delete from vault.secrets where id = current_refs.access_token_id;
  end if;
  if current_refs.webhook_secret_id is distinct from next_webhook_secret_id
      and current_refs.webhook_secret_id is not null then
    delete from vault.secrets where id = current_refs.webhook_secret_id;
  end if;
  if current_refs.email_api_key_id is distinct from next_email_api_key_id
      and current_refs.email_api_key_id is not null then
    delete from vault.secrets where id = current_refs.email_api_key_id;
  end if;
end;
$$;

revoke all on function public.save_payment_configuration(text, text, text, text)
  from public, anon;
grant execute on function public.save_payment_configuration(text, text, text, text)
  to authenticated;

create or replace function public.get_payment_configuration()
returns table (
  access_token text,
  webhook_secret text,
  email_api_key text,
  email_from text
)
language sql
security definer
set search_path = ''
as $$
  select access_secret.decrypted_secret,
         webhook_secret.decrypted_secret,
         email_secret.decrypted_secret,
         refs.email_from
  from private.payment_secret_refs refs
  left join vault.decrypted_secrets access_secret
    on access_secret.id = refs.access_token_id
  left join vault.decrypted_secrets webhook_secret
    on webhook_secret.id = refs.webhook_secret_id
  left join vault.decrypted_secrets email_secret
    on email_secret.id = refs.email_api_key_id
  where refs.singleton = true;
$$;

revoke all on function public.get_payment_configuration() from public, anon, authenticated;
grant execute on function public.get_payment_configuration() to service_role;

create or replace function public.get_admin_overview(
  p_limit integer default 100,
  p_offset integer default 0
)
returns jsonb
language sql
security definer
set search_path = ''
as $$
  with user_metrics as (
    select u.id,
           u.email,
           u.created_at,
           coalesce(p.full_name, '') as full_name,
           coalesce(c.initial_balance, 0) as initial_balance,
           coalesce(s.sales_revenue, 0) as sales_revenue,
           coalesce(sp.service_revenue, 0) as service_revenue,
           coalesce(w.withdrawals, 0) as withdrawals,
           coalesce(costs.costs, 0) as costs,
           coalesce(s.sales_revenue, 0)
             + coalesce(sp.service_revenue, 0)
             + coalesce(c.initial_balance, 0)
             - coalesce(w.withdrawals, 0)
             - coalesce(costs.costs, 0) as cash_balance
    from auth.users u
    left join public.profiles p on p.id = u.id
    left join public.cash_settings c on c.user_id = u.id
    left join lateral (
      select sum(s.quantity * s.unit_price) as sales_revenue
      from public.sales s
      where s.user_id = u.id and s.status = 'active'
    ) s on true
    left join lateral (
      select sum(sp.amount) as service_revenue
      from public.service_payments sp
      where sp.user_id = u.id and sp.status = 'active'
    ) sp on true
    left join lateral (
      select sum(w.amount) as withdrawals
      from public.withdrawals w
      where w.user_id = u.id and w.status = 'active'
    ) w on true
    left join lateral (
      select sum(cost.amount) as costs
      from public.costs cost
      where cost.user_id = u.id and cost.status = 'active'
    ) costs on true
    where u.email_confirmed_at is not null
  ),
  totals as (
    select
      (select count(*) from auth.users where email_confirmed_at is not null) as total_accounts,
      (select count(*) from public.invite_purchases where status = 'approved') as invitations_sold,
      (select coalesce(sum(amount), 0) from public.invite_purchases where status = 'approved') as invitation_revenue,
      (select count(*) from public.invite_purchases where status = 'pending') as pending_payments
  ),
  recent_invitations as (
    select coalesce(
      jsonb_agg(
        jsonb_build_object(
          'id', recent.id,
          'email', recent.email,
          'amount', recent.amount,
          'status', recent.status,
          'createdAt', recent.created_at
        ) order by recent.created_at desc
      ),
      '[]'::jsonb
    ) as invitations
    from (
      select id, email, amount, status, created_at
      from public.invite_purchases
      order by created_at desc
      limit 100
    ) recent
  ),
  config as (
    select refs.access_token_id is not null as payment_configured,
           refs.webhook_secret_id is not null as webhook_configured,
           refs.email_api_key_id is not null and nullif(refs.email_from, '') is not null as email_configured
    from private.payment_secret_refs refs
    where refs.singleton = true
  ),
  latest_users as (
    select coalesce(
      jsonb_agg(
        jsonb_build_object(
          'id', recent.id,
          'email', recent.email,
          'fullName', recent.full_name,
          'createdAt', recent.created_at,
          'cashBalance', recent.cash_balance,
          'salesRevenue', recent.sales_revenue,
          'serviceRevenue', recent.service_revenue,
          'withdrawals', recent.withdrawals,
          'costs', recent.costs
        ) order by recent.created_at desc
      ),
      '[]'::jsonb
    ) as users
    from (
      select * from user_metrics
      order by created_at desc
      limit greatest(1, least(coalesce(p_limit, 100), 200))
      offset greatest(0, least(coalesce(p_offset, 0), 1000000))
    ) recent
  )
  select jsonb_build_object(
    'totalAccounts', totals.total_accounts,
    'invitationsSold', totals.invitations_sold,
    'invitationRevenue', totals.invitation_revenue,
    'pendingPayments', totals.pending_payments,
    'paymentConfigured', coalesce(config.payment_configured, false),
    'webhookConfigured', coalesce(config.webhook_configured, false),
    'emailConfigured', coalesce(config.email_configured, false),
    'recentInvitations', recent_invitations.invitations,
    'users', latest_users.users
  )
  from totals
  cross join latest_users
  cross join recent_invitations
  left join config on true;
$$;

revoke all on function public.get_admin_overview(integer, integer) from public, anon, authenticated;
grant execute on function public.get_admin_overview(integer, integer) to service_role;

insert into storage.buckets (id, name, public)
values ('app-branding', 'app-branding', true)
on conflict (id) do update set public = true;

drop policy if exists "Public can read app branding" on storage.objects;
create policy "Public can read app branding"
  on storage.objects for select to anon, authenticated
  using (bucket_id = 'app-branding');

drop policy if exists "Admins manage app branding" on storage.objects;
create policy "Admins manage app branding"
  on storage.objects for all to authenticated
  using (bucket_id = 'app-branding' and public.is_app_admin())
  with check (bucket_id = 'app-branding' and public.is_app_admin());

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.cash_settings enable row level security;
alter table public.sales enable row level security;
alter table public.service_orders enable row level security;
alter table public.service_payments enable row level security;
alter table public.withdrawals enable row level security;
alter table public.costs enable row level security;
alter table public.cash_adjustments enable row level security;

create policy "Users manage own profile" on public.profiles for all to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
create policy "Users manage own cash settings" on public.cash_settings for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Users manage own sales" on public.sales for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Users manage own service orders" on public.service_orders for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Users manage own service payments" on public.service_payments for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Users manage own withdrawals" on public.withdrawals for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Users manage own costs" on public.costs for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Users read own cash adjustments" on public.cash_adjustments for select to authenticated
  using ((select auth.uid()) = user_id);

grant select, insert, update, delete on public.profiles, public.cash_settings, public.sales,
  public.service_orders, public.service_payments, public.withdrawals, public.costs to authenticated;
grant select on public.cash_adjustments to authenticated;

create table public.app_settings (
  singleton boolean primary key default true check (singleton),
  invitation_price numeric(10,2) not null default 0 check (invitation_price >= 0),
  maintenance_mode boolean not null default false,
  updated_at timestamptz not null default now()
);

insert into public.app_settings (singleton)
values (true)
on conflict (singleton) do nothing;

create or replace function public.is_app_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from auth.users u
    where u.id = (select auth.uid())
      and lower(u.email) = 'alexandremoderbr@gmail.com'
      and u.email_confirmed_at is not null
  );
$$;

grant execute on function public.is_app_admin() to anon, authenticated, service_role;

create table public.invite_purchases (
  id uuid primary key default gen_random_uuid(),
  checkout_token uuid not null unique default gen_random_uuid(),
  email text not null,
  amount numeric(10,2) not null check (amount > 0),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'cancelled')),
  provider_payment_id text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.invitation_codes (
  code text primary key,
  purchase_id uuid not null unique references public.invite_purchases (id) on delete cascade,
  expires_at timestamptz not null,
  used_by uuid unique references auth.users (id) on delete set null,
  email_sent_at timestamptz,
  created_at timestamptz not null default now()
);

create index invitation_codes_available_idx
  on public.invitation_codes (expires_at)
  where used_by is null;

create table public.app_changelogs (
  id uuid primary key default gen_random_uuid(),
  version text not null,
  title text not null,
  description text not null,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);

alter table public.app_settings enable row level security;
alter table public.invite_purchases enable row level security;
alter table public.invitation_codes enable row level security;
alter table public.app_changelogs enable row level security;

create policy "Anyone can read app settings"
  on public.app_settings for select to anon, authenticated
  using (true);
create policy "Admins update app settings"
  on public.app_settings for update to authenticated
  using (public.is_app_admin())
  with check (public.is_app_admin());

create policy "Anyone can read changelogs"
  on public.app_changelogs for select to anon, authenticated
  using (true);
create policy "Admins manage changelogs"
  on public.app_changelogs for all to authenticated
  using (public.is_app_admin())
  with check (public.is_app_admin());

revoke all on public.invite_purchases, public.invitation_codes from anon, authenticated;
grant all on public.invite_purchases, public.invitation_codes to service_role;
grant select on public.app_settings, public.app_changelogs to anon, authenticated;
grant update on public.app_settings to authenticated;
grant insert, update, delete on public.app_changelogs to authenticated;

create or replace function public.fulfill_invitation_purchase(
  p_purchase_id uuid,
  p_payment_id text,
  p_code text
)
returns table (email text, code text, expires_at timestamptz, email_sent_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  purchase_status text;
begin
  select p.status
    into purchase_status
    from public.invite_purchases p
    where p.id = p_purchase_id
    for update;

  if not found then
    raise exception 'Compra de convite não encontrada.';
  end if;

  if purchase_status = 'approved' then
    return query
      select p.email, i.code, i.expires_at, i.email_sent_at
      from public.invite_purchases p
      join public.invitation_codes i on i.purchase_id = p.id
      where p.id = p_purchase_id;
    return;
  end if;

  update public.invite_purchases
    set status = 'approved',
        provider_payment_id = p_payment_id,
        updated_at = now()
    where id = p_purchase_id;

  insert into public.invitation_codes (code, purchase_id, expires_at)
    values (upper(p_code), p_purchase_id, now() + interval '24 hours');

  return query
    select p.email, i.code, i.expires_at, i.email_sent_at
    from public.invite_purchases p
    join public.invitation_codes i on i.purchase_id = p.id
    where p.id = p_purchase_id;
end;
$$;

revoke all on function public.fulfill_invitation_purchase(uuid, text, text) from public, anon, authenticated;
grant execute on function public.fulfill_invitation_purchase(uuid, text, text) to service_role;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  consumed_code text;
begin
  if lower(coalesce(new.email, '')) <> 'alexandremoderbr@gmail.com' then
    update public.invitation_codes
      set used_by = new.id
      where code = upper(coalesce(new.raw_user_meta_data ->> 'invitation_code', ''))
        and used_by is null
        and expires_at > now()
      returning code into consumed_code;

    if consumed_code is null then
      raise exception 'Código de convite inválido, expirado ou já utilizado.';
    end if;
  end if;

  insert into public.profiles (id, full_name)
    values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''));
  insert into public.cash_settings (user_id, initial_balance)
    values (new.id, 0);
  return new;
end;
$$;
