PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS customers (
  customer_id TEXT PRIMARY KEY,
  customer_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
  site_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  site_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(customer_id) REFERENCES customers(customer_id)
);

CREATE TABLE IF NOT EXISTS vcenters (
  vcenter_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 443,
  username TEXT,
  ssl_verify INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(customer_id) REFERENCES customers(customer_id),
  FOREIGN KEY(site_id) REFERENCES sites(site_id)
);

CREATE TABLE IF NOT EXISTS inspection_runs (
  run_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  vcenter_id TEXT NOT NULL,
  trigger_type TEXT NOT NULL,
  run_status TEXT NOT NULL,
  current_stage TEXT,
  progress_percent INTEGER NOT NULL DEFAULT 0,
  asset_summary_json TEXT,
  risk_summary_json TEXT,
  risk_category_summary_json TEXT,
  score REAL,
  error_message TEXT,
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(customer_id) REFERENCES customers(customer_id),
  FOREIGN KEY(site_id) REFERENCES sites(site_id),
  FOREIGN KEY(vcenter_id) REFERENCES vcenters(vcenter_id)
);

CREATE TABLE IF NOT EXISTS inventory_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  vcenter_id TEXT NOT NULL,
  snapshot_type TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  object_count INTEGER NOT NULL DEFAULT 0,
  summary_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES inspection_runs(run_id)
);

CREATE TABLE IF NOT EXISTS inventory_objects (
  object_id TEXT PRIMARY KEY,
  snapshot_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  vcenter_id TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  object_name TEXT NOT NULL,
  path TEXT,
  properties_json TEXT,
  raw_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(snapshot_id) REFERENCES inventory_snapshots(snapshot_id),
  UNIQUE(snapshot_id, object_type, object_key)
);

CREATE TABLE IF NOT EXISTS rules (
  rule_id TEXT PRIMARY KEY,
  rule_name TEXT NOT NULL,
  category TEXT NOT NULL,
  object_type TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  confidence_level TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  definition_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_results (
  result_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  vcenter_id TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  object_name TEXT NOT NULL,
  object_path TEXT,
  result_status TEXT NOT NULL,
  risk_level TEXT,
  confidence_level TEXT,
  observed_value TEXT,
  expected_value TEXT,
  evidence_json TEXT,
  raw_json TEXT,
  error_message TEXT,
  evaluated_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES inspection_runs(run_id)
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY,
  finding_key TEXT NOT NULL UNIQUE,
  customer_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  vcenter_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  latest_result_id TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  object_name TEXT NOT NULL,
  title TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  confidence_level TEXT NOT NULL,
  status TEXT NOT NULL,
  exception_reason TEXT,
  exception_owner TEXT,
  exception_expires_at TEXT,
  exception_approval_note TEXT,
  resolved_run_id TEXT,
  resolved_at TEXT,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  remediation_status TEXT NOT NULL DEFAULT 'open',
  first_seen_run_id TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_run_id TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_exceptions (
  exception_id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  finding_key TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  vcenter_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  exception_reason TEXT NOT NULL,
  owner TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  approval_note TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS reports (
  report_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  vcenter_id TEXT NOT NULL,
  report_name TEXT NOT NULL,
  report_type TEXT NOT NULL,
  report_status TEXT NOT NULL,
  file_path TEXT,
  generated_at TEXT,
  error_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES inspection_runs(run_id)
);

CREATE TABLE IF NOT EXISTS log_analysis_runs (
  log_run_id TEXT PRIMARY KEY,
  customer_name TEXT NOT NULL,
  report_title TEXT NOT NULL,
  support_bundle_path TEXT NOT NULL,
  support_bundle_name TEXT NOT NULL,
  problem_description TEXT NOT NULL,
  run_status TEXT NOT NULL,
  current_stage TEXT,
  progress_percent INTEGER NOT NULL DEFAULT 0,
  summary_json TEXT,
  error_message TEXT,
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_analysis_reports (
  report_id TEXT PRIMARY KEY,
  log_run_id TEXT NOT NULL,
  report_name TEXT NOT NULL,
  report_type TEXT NOT NULL,
  report_status TEXT NOT NULL,
  file_path TEXT,
  generated_at TEXT,
  error_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(log_run_id) REFERENCES log_analysis_runs(log_run_id)
);

-- Upgrade compatibility is deliberately separate from the inspection domain.
CREATE TABLE IF NOT EXISTS upgrade_compat_runs (
  run_id TEXT PRIMARY KEY,
  customer_name TEXT NOT NULL,
  report_title TEXT NOT NULL,
  target_release TEXT NOT NULL,
  collection_mode TEXT NOT NULL CHECK(collection_mode IN ('vcenter', 'support_bundle')),
  vcenter_host TEXT,
  bundle_path TEXT,
  vsan_check_mode TEXT NOT NULL CHECK(vsan_check_mode IN ('auto', 'force', 'skip')),
  vcg_data_version_id TEXT,
  vsan_data_version_id TEXT,
  run_status TEXT NOT NULL,
  current_stage TEXT,
  progress_percent INTEGER NOT NULL DEFAULT 0,
  summary_json TEXT,
  error_message TEXT,
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS upgrade_compat_reports (
  report_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  report_name TEXT NOT NULL,
  report_type TEXT NOT NULL,
  report_status TEXT NOT NULL,
  file_path TEXT,
  generated_at TEXT,
  error_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES upgrade_compat_runs(run_id)
);

CREATE TABLE IF NOT EXISTS hcl_data_versions (
  data_version_id TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  downloaded_at TEXT NOT NULL,
  json_updated_time TEXT,
  total_count INTEGER NOT NULL DEFAULT 0,
  checksum_sha256 TEXT NOT NULL,
  supported_releases_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hcl_devices (
  hcl_device_id TEXT PRIMARY KEY,
  data_version_id TEXT NOT NULL,
  category TEXT NOT NULL,
  external_id TEXT NOT NULL,
  model TEXT NOT NULL,
  vendor TEXT NOT NULL,
  vid TEXT NOT NULL,
  did TEXT NOT NULL,
  svid TEXT NOT NULL,
  ssid TEXT NOT NULL,
  server_smbios_models_json TEXT NOT NULL DEFAULT '[]',
  vcglink TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(data_version_id) REFERENCES hcl_data_versions(data_version_id)
);
CREATE INDEX IF NOT EXISTS idx_hcl_devices_quadruple ON hcl_devices(vid, did, svid, ssid);

CREATE TABLE IF NOT EXISTS hcl_device_releases (
  hcl_device_id TEXT NOT NULL,
  release TEXT NOT NULL,
  driver_name TEXT NOT NULL,
  driver_version TEXT NOT NULL,
  firmware_version TEXT,
  driver_spec_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY(hcl_device_id) REFERENCES hcl_devices(hcl_device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_hcl_releases_quadruple ON hcl_device_releases(hcl_device_id, release, driver_name, driver_version, firmware_version);
