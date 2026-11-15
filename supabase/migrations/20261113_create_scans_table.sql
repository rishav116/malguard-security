-- MALGUARD AI — Scan History Table with Row Level Security (RLS)
-- Phase 4C: ClamAV Integration + Persistent Scan History
-- Run this migration in your Supabase SQL Editor: https://supabase.com/dashboard/project/_/sql

create table if not exists public.scans (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    file_name text not null,
    file_size_bytes bigint not null,
    formatted_size text not null,
    sha256 text not null,
    sha1 text,
    md5 text,
    verdict text not null check (verdict in ('MALICIOUS', 'SUSPICIOUS', 'NO_THREAT_DETECTED', 'INCONCLUSIVE')),
    verdict_reasons jsonb not null default '[]'::jsonb,
    
    -- PE analysis summary metadata (never stores binary content)
    pe_summary jsonb not null default '{}'::jsonb,
    
    -- ClamAV engine findings
    clamav_status text not null,
    clamav_available boolean not null default false,
    clamav_matched boolean not null default false,
    clamav_signature text,
    clamav_message text,
    
    -- Machine Learning classifier findings
    ml_status text not null,
    ml_available boolean not null default false,
    ml_prediction text,
    ml_confidence_score double precision,
    ml_message text,
    
    created_at timestamptz not null default now()
);

-- Indexes for performance
create index if not exists idx_scans_user_id on public.scans(user_id);
create index if not exists idx_scans_created_at on public.scans(created_at desc);
create index if not exists idx_scans_verdict on public.scans(verdict);
create index if not exists idx_scans_sha256 on public.scans(sha256);

-- Enable Row Level Security (RLS)
alter table public.scans enable row level security;

-- Policy 1: Users can view only their own scans
drop policy if exists "Users can view their own scans" on public.scans;
create policy "Users can view their own scans"
    on public.scans
    for select
    using (auth.uid() = user_id);

-- Policy 2: Users can insert only scans belonging to themselves
drop policy if exists "Users can insert their own scans" on public.scans;
create policy "Users can insert their own scans"
    on public.scans
    for insert
    with check (auth.uid() = user_id);

-- Policy 3: Users can delete only their own scans
drop policy if exists "Users can delete their own scans" on public.scans;
create policy "Users can delete their own scans"
    on public.scans
    for delete
    using (auth.uid() = user_id);

