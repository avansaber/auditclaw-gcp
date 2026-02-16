"""Tests for GCP compliance check modules (18 tests with mocked GCP clients)."""

import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

PROJECT_ID = "test-project-123"


# ---------------------------------------------------------------------------
# Storage Tests (2)
# ---------------------------------------------------------------------------

class TestStorageChecks:
    @patch("checks.storage.storage")
    def test_storage_compliant(self, mock_storage):
        from checks.storage import run_storage_checks

        bucket = MagicMock()
        bucket.name = "secure-bucket"
        bucket.iam_configuration.uniform_bucket_level_access_enabled = True
        bucket.iam_configuration.public_access_prevention = "enforced"

        client = MagicMock()
        client.list_buckets.return_value = [bucket]
        mock_storage.Client.return_value = client

        result = run_storage_checks(PROJECT_ID)
        assert result["check"] == "storage"
        assert result["provider"] == "gcp"
        assert result["status"] == "pass"
        assert result["passed"] == 2
        assert result["failed"] == 0

    @patch("checks.storage.storage")
    def test_storage_non_compliant(self, mock_storage):
        from checks.storage import run_storage_checks

        bucket = MagicMock()
        bucket.name = "legacy-bucket"
        bucket.iam_configuration.uniform_bucket_level_access_enabled = False
        bucket.iam_configuration.public_access_prevention = "inherited"

        client = MagicMock()
        client.list_buckets.return_value = [bucket]
        mock_storage.Client.return_value = client

        result = run_storage_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] == 2
        assert result["passed"] == 0


# ---------------------------------------------------------------------------
# Firewall Tests (2)
# ---------------------------------------------------------------------------

class TestFirewallChecks:
    @patch("checks.firewall.FirewallsClient")
    def test_firewall_compliant(self, mock_fw_cls):
        from checks.firewall import run_firewall_checks

        # No rules with 0.0.0.0/0
        rule = MagicMock()
        rule.direction = "INGRESS"
        rule.source_ranges = ["10.0.0.0/8"]
        rule.name = "allow-internal"
        rule.allowed = []

        mock_fw_cls.return_value.list.return_value = [rule]

        result = run_firewall_checks(PROJECT_ID)
        assert result["check"] == "firewall"
        assert result["status"] == "pass"
        assert result["passed"] == 1

    @patch("checks.firewall.FirewallsClient")
    def test_firewall_non_compliant(self, mock_fw_cls):
        from checks.firewall import run_firewall_checks

        # Rule with SSH + RDP open to 0.0.0.0/0
        ssh_allowed = MagicMock()
        ssh_allowed.I_p_protocol = "tcp"
        ssh_allowed.ip_protocol = "tcp"
        ssh_allowed.ports = ["22"]

        rdp_allowed = MagicMock()
        rdp_allowed.I_p_protocol = "tcp"
        rdp_allowed.ip_protocol = "tcp"
        rdp_allowed.ports = ["3389"]

        rule = MagicMock()
        rule.direction = "INGRESS"
        rule.source_ranges = ["0.0.0.0/0"]
        rule.name = "allow-all-ssh-rdp"
        rule.allowed = [ssh_allowed, rdp_allowed]

        mock_fw_cls.return_value.list.return_value = [rule]

        result = run_firewall_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] >= 2


# ---------------------------------------------------------------------------
# IAM Key Rotation Tests (2)
# ---------------------------------------------------------------------------

class TestIAMKeyRotationChecks:
    @patch("checks.iam.ProjectsClient")
    @patch("checks.iam.ListServiceAccountKeysRequest")
    @patch("checks.iam.IAMClient")
    def test_iam_keys_compliant(self, mock_iam_cls, mock_key_req, mock_rm_cls):
        from checks.iam import run_iam_checks

        # Service account with fresh key
        sa = MagicMock()
        sa.name = "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com"
        sa.email = "sa@test.iam.gserviceaccount.com"

        key = MagicMock()
        key.name = "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com/keys/key123"
        key.key_type = 1  # USER_MANAGED
        key.valid_after_time = datetime.now(timezone.utc) - timedelta(days=30)

        iam_client = mock_iam_cls.return_value
        iam_client.list_service_accounts.return_value = [sa]
        key_response = MagicMock()
        key_response.keys = [key]
        iam_client.list_service_account_keys.return_value = key_response

        # No admin bindings
        policy = MagicMock()
        policy.bindings = []
        mock_rm_cls.return_value.get_iam_policy.return_value = policy

        result = run_iam_checks(PROJECT_ID)
        assert result["check"] == "iam"
        assert result["status"] == "pass"
        assert result["passed"] >= 2

    @patch("checks.iam.ProjectsClient")
    @patch("checks.iam.ListServiceAccountKeysRequest")
    @patch("checks.iam.IAMClient")
    def test_iam_keys_non_compliant(self, mock_iam_cls, mock_key_req, mock_rm_cls):
        from checks.iam import run_iam_checks

        # Service account with old key (> 90 days)
        sa = MagicMock()
        sa.name = "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com"
        sa.email = "sa@test.iam.gserviceaccount.com"

        key = MagicMock()
        key.name = "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com/keys/key456"
        key.key_type = 1  # USER_MANAGED
        key.valid_after_time = datetime.now(timezone.utc) - timedelta(days=120)

        iam_client = mock_iam_cls.return_value
        iam_client.list_service_accounts.return_value = [sa]
        key_response = MagicMock()
        key_response.keys = [key]
        iam_client.list_service_account_keys.return_value = key_response

        # No admin bindings
        policy = MagicMock()
        policy.bindings = []
        mock_rm_cls.return_value.get_iam_policy.return_value = policy

        result = run_iam_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] >= 1


# ---------------------------------------------------------------------------
# IAM Admin Privilege Tests (2)
# ---------------------------------------------------------------------------

class TestIAMAdminChecks:
    @patch("checks.iam.ProjectsClient")
    @patch("checks.iam.ListServiceAccountKeysRequest")
    @patch("checks.iam.IAMClient")
    def test_iam_admin_compliant(self, mock_iam_cls, mock_key_req, mock_rm_cls):
        from checks.iam import run_iam_checks

        # No service accounts
        iam_client = mock_iam_cls.return_value
        iam_client.list_service_accounts.return_value = []

        # No SA with owner/editor
        binding = MagicMock()
        binding.role = "roles/viewer"
        binding.members = ["user:test-admin@company.example"]

        policy = MagicMock()
        policy.bindings = [binding]
        mock_rm_cls.return_value.get_iam_policy.return_value = policy

        result = run_iam_checks(PROJECT_ID)
        assert result["status"] == "pass"

    @patch("checks.iam.ProjectsClient")
    @patch("checks.iam.ListServiceAccountKeysRequest")
    @patch("checks.iam.IAMClient")
    def test_iam_admin_non_compliant(self, mock_iam_cls, mock_key_req, mock_rm_cls):
        from checks.iam import run_iam_checks

        # No service accounts
        iam_client = mock_iam_cls.return_value
        iam_client.list_service_accounts.return_value = []

        # SA with roles/owner
        binding = MagicMock()
        binding.role = "roles/owner"
        binding.members = ["serviceAccount:sa@test.iam.gserviceaccount.com"]

        policy = MagicMock()
        policy.bindings = [binding]
        mock_rm_cls.return_value.get_iam_policy.return_value = policy

        result = run_iam_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] >= 1


# ---------------------------------------------------------------------------
# Logging Audit Tests (2)
# ---------------------------------------------------------------------------

class TestLoggingAuditChecks:
    @patch("checks.gcp_logging.LoggingClient")
    @patch("checks.gcp_logging.ProjectsClient")
    def test_logging_audit_compliant(self, mock_rm_cls, mock_log_cls):
        from checks.gcp_logging import run_logging_checks

        # All log types enabled for allServices
        log_config_1 = MagicMock()
        log_config_1.log_type = 1  # ADMIN_READ
        log_config_2 = MagicMock()
        log_config_2.log_type = 2  # DATA_WRITE
        log_config_3 = MagicMock()
        log_config_3.log_type = 3  # DATA_READ

        audit_config = MagicMock()
        audit_config.service = "allServices"
        audit_config.audit_log_configs = [log_config_1, log_config_2, log_config_3]

        policy = MagicMock()
        policy.audit_configs = [audit_config]
        mock_rm_cls.return_value.get_iam_policy.return_value = policy

        # Sink with no filter
        sink = MagicMock()
        sink.name = "export-all"
        sink.filter_ = ""

        mock_log_cls.return_value.list_sinks.return_value = [sink]

        result = run_logging_checks(PROJECT_ID)
        assert result["check"] == "logging"
        assert result["status"] == "pass"
        assert result["passed"] == 2

    @patch("checks.gcp_logging.LoggingClient")
    @patch("checks.gcp_logging.ProjectsClient")
    def test_logging_non_compliant(self, mock_rm_cls, mock_log_cls):
        from checks.gcp_logging import run_logging_checks

        # No audit configs
        policy = MagicMock()
        policy.audit_configs = []
        mock_rm_cls.return_value.get_iam_policy.return_value = policy

        # No sinks
        mock_log_cls.return_value.list_sinks.return_value = []

        result = run_logging_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] == 2


# ---------------------------------------------------------------------------
# Logging Sink Tests (2)
# ---------------------------------------------------------------------------

class TestLoggingSinkChecks:
    @patch("checks.gcp_logging.LoggingClient")
    @patch("checks.gcp_logging.ProjectsClient")
    def test_logging_sink_compliant(self, mock_rm_cls, mock_log_cls):
        from checks.gcp_logging import run_logging_checks

        # Audit config present
        log_config_1 = MagicMock()
        log_config_1.log_type = 1
        log_config_2 = MagicMock()
        log_config_2.log_type = 2
        log_config_3 = MagicMock()
        log_config_3.log_type = 3

        audit_config = MagicMock()
        audit_config.service = "allServices"
        audit_config.audit_log_configs = [log_config_1, log_config_2, log_config_3]

        policy = MagicMock()
        policy.audit_configs = [audit_config]
        mock_rm_cls.return_value.get_iam_policy.return_value = policy

        # Sink with no filter
        sink = MagicMock()
        sink.name = "all-logs-sink"
        sink.filter_ = ""
        mock_log_cls.return_value.list_sinks.return_value = [sink]

        result = run_logging_checks(PROJECT_ID)
        assert result["status"] == "pass"
        sink_finding = [f for f in result["findings"] if "export-sink" in f["resource"]]
        assert len(sink_finding) == 1
        assert sink_finding[0]["status"] == "pass"

    @patch("checks.gcp_logging.LoggingClient")
    @patch("checks.gcp_logging.ProjectsClient")
    def test_logging_sink_missing(self, mock_rm_cls, mock_log_cls):
        from checks.gcp_logging import run_logging_checks

        # Valid audit config
        log_config_1 = MagicMock()
        log_config_1.log_type = 1
        log_config_2 = MagicMock()
        log_config_2.log_type = 2
        log_config_3 = MagicMock()
        log_config_3.log_type = 3

        audit_config = MagicMock()
        audit_config.service = "allServices"
        audit_config.audit_log_configs = [log_config_1, log_config_2, log_config_3]

        policy = MagicMock()
        policy.audit_configs = [audit_config]
        mock_rm_cls.return_value.get_iam_policy.return_value = policy

        # No sinks
        mock_log_cls.return_value.list_sinks.return_value = []

        result = run_logging_checks(PROJECT_ID)
        sink_finding = [f for f in result["findings"] if "export-sink" in f["resource"]]
        assert len(sink_finding) == 1
        assert sink_finding[0]["status"] == "fail"


# ---------------------------------------------------------------------------
# KMS Tests (2)
# ---------------------------------------------------------------------------

class TestKMSChecks:
    @patch("checks.kms.KeyManagementServiceClient")
    def test_kms_compliant(self, mock_kms_cls):
        from checks.kms import run_kms_checks

        key_ring = MagicMock()
        key_ring.name = "projects/test/locations/us/keyRings/my-ring"

        crypto_key = MagicMock()
        crypto_key.name = "projects/test/locations/us/keyRings/my-ring/cryptoKeys/my-key"
        crypto_key.purpose = 1  # ENCRYPT_DECRYPT
        crypto_key.rotation_period = timedelta(days=90)

        kms_client = mock_kms_cls.return_value
        kms_client.list_key_rings.return_value = [key_ring]
        kms_client.list_crypto_keys.return_value = [crypto_key]

        result = run_kms_checks(PROJECT_ID)
        assert result["check"] == "kms"
        assert result["status"] == "pass"
        assert result["passed"] == 1

    @patch("checks.kms.KeyManagementServiceClient")
    def test_kms_non_compliant(self, mock_kms_cls):
        from checks.kms import run_kms_checks

        key_ring = MagicMock()
        key_ring.name = "projects/test/locations/us/keyRings/my-ring"

        crypto_key = MagicMock()
        crypto_key.name = "projects/test/locations/us/keyRings/my-ring/cryptoKeys/no-rotation"
        crypto_key.purpose = 1
        crypto_key.rotation_period = timedelta(seconds=0)

        kms_client = mock_kms_cls.return_value
        kms_client.list_key_rings.return_value = [key_ring]
        kms_client.list_crypto_keys.return_value = [crypto_key]

        result = run_kms_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] == 1


# ---------------------------------------------------------------------------
# DNS Tests (2)
# ---------------------------------------------------------------------------

class TestDNSChecks:
    @patch("checks.dns.dns")
    def test_dns_compliant(self, mock_dns):
        from checks.dns import run_dns_checks

        zone = MagicMock()
        zone.name = "example-zone"
        zone.visibility = "public"
        zone.dnssec_config = {"state": "on"}

        client = MagicMock()
        client.list_zones.return_value = [zone]
        mock_dns.Client.return_value = client

        result = run_dns_checks(PROJECT_ID)
        assert result["check"] == "dns"
        assert result["status"] == "pass"
        assert result["passed"] == 1

    @patch("checks.dns.dns")
    def test_dns_non_compliant(self, mock_dns):
        from checks.dns import run_dns_checks

        zone = MagicMock()
        zone.name = "insecure-zone"
        zone.visibility = "public"
        zone.dnssec_config = {"state": "off"}

        client = MagicMock()
        client.list_zones.return_value = [zone]
        mock_dns.Client.return_value = client

        result = run_dns_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] == 1


# ---------------------------------------------------------------------------
# BigQuery Tests (2)
# ---------------------------------------------------------------------------

class TestBigQueryChecks:
    @patch("checks.bigquery.bigquery")
    def test_bigquery_compliant(self, mock_bq):
        from checks.bigquery import run_bigquery_checks

        dataset_ref = MagicMock()
        dataset_ref.dataset_id = "private-dataset"
        dataset_ref.reference = "projects/test/datasets/private-dataset"

        entry = MagicMock()
        entry.entity_id = "user@example.com"

        dataset = MagicMock()
        dataset.access_entries = [entry]

        client = MagicMock()
        client.list_datasets.return_value = [dataset_ref]
        client.get_dataset.return_value = dataset
        mock_bq.Client.return_value = client

        result = run_bigquery_checks(PROJECT_ID)
        assert result["check"] == "bigquery"
        assert result["status"] == "pass"
        assert result["passed"] == 1

    @patch("checks.bigquery.bigquery")
    def test_bigquery_non_compliant(self, mock_bq):
        from checks.bigquery import run_bigquery_checks

        dataset_ref = MagicMock()
        dataset_ref.dataset_id = "public-dataset"
        dataset_ref.reference = "projects/test/datasets/public-dataset"

        entry = MagicMock()
        entry.entity_id = "allUsers"

        dataset = MagicMock()
        dataset.access_entries = [entry]

        client = MagicMock()
        client.list_datasets.return_value = [dataset_ref]
        client.get_dataset.return_value = dataset
        mock_bq.Client.return_value = client

        result = run_bigquery_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] == 1


# ---------------------------------------------------------------------------
# Compute Tests (2)
# ---------------------------------------------------------------------------

class TestComputeChecks:
    @patch("checks.compute.InstancesClient")
    def test_compute_compliant(self, mock_inst_cls):
        from checks.compute import run_compute_checks

        sa = MagicMock()
        sa.email = "custom-sa@test.iam.gserviceaccount.com"
        sa.scopes = ["https://www.googleapis.com/auth/devstorage.read_only"]

        instance = MagicMock()
        instance.name = "secure-vm"
        instance.service_accounts = [sa]

        response = MagicMock()
        response.instances = [instance]

        mock_inst_cls.return_value.aggregated_list.return_value = [
            ("zones/us-central1-a", response)
        ]

        result = run_compute_checks(PROJECT_ID)
        assert result["check"] == "compute"
        assert result["status"] == "pass"
        assert result["passed"] == 1

    @patch("checks.compute.InstancesClient")
    def test_compute_non_compliant(self, mock_inst_cls):
        from checks.compute import run_compute_checks

        sa = MagicMock()
        sa.email = "123456789-compute@developer.gserviceaccount.com"
        sa.scopes = ["https://www.googleapis.com/auth/cloud-platform"]

        instance = MagicMock()
        instance.name = "insecure-vm"
        instance.service_accounts = [sa]

        response = MagicMock()
        response.instances = [instance]

        mock_inst_cls.return_value.aggregated_list.return_value = [
            ("zones/us-central1-a", response)
        ]

        result = run_compute_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] == 1


# ---------------------------------------------------------------------------
# Cloud SQL Tests (2)
# ---------------------------------------------------------------------------

class TestCloudSQLChecks:
    @patch("checks.cloudsql.google.auth")
    @patch("checks.cloudsql.build")
    def test_cloudsql_compliant(self, mock_build, mock_auth):
        from checks.cloudsql import run_cloudsql_checks

        mock_auth.default.return_value = (MagicMock(), "test-project")

        instances_data = {
            "items": [{
                "name": "secure-db",
                "settings": {
                    "ipConfiguration": {
                        "requireSsl": True,
                        "ipv4Enabled": False,
                        "authorizedNetworks": [],
                    }
                }
            }]
        }

        sqladmin = MagicMock()
        sqladmin.instances.return_value.list.return_value.execute.return_value = instances_data
        mock_build.return_value = sqladmin

        result = run_cloudsql_checks(PROJECT_ID)
        assert result["check"] == "cloudsql"
        assert result["status"] == "pass"
        assert result["passed"] == 2

    @patch("checks.cloudsql.google.auth")
    @patch("checks.cloudsql.build")
    def test_cloudsql_non_compliant(self, mock_build, mock_auth):
        from checks.cloudsql import run_cloudsql_checks

        mock_auth.default.return_value = (MagicMock(), "test-project")

        instances_data = {
            "items": [{
                "name": "insecure-db",
                "settings": {
                    "ipConfiguration": {
                        "requireSsl": False,
                        "ipv4Enabled": True,
                        "authorizedNetworks": [{"value": "0.0.0.0/0"}],
                    }
                }
            }]
        }

        sqladmin = MagicMock()
        sqladmin.instances.return_value.list.return_value.execute.return_value = instances_data
        mock_build.return_value = sqladmin

        result = run_cloudsql_checks(PROJECT_ID)
        assert result["status"] == "fail"
        assert result["failed"] == 2


# ---------------------------------------------------------------------------
# Orchestrator Tests (1 -- ensures ALL_CHECKS registry is correct)
# ---------------------------------------------------------------------------

class TestOrchestrator:
    def test_all_checks_registered(self):
        from checks import ALL_CHECKS
        expected = {
            "storage", "firewall", "iam", "logging", "kms",
            "dns", "bigquery", "compute", "cloudsql",
        }
        assert set(ALL_CHECKS.keys()) == expected
        assert len(ALL_CHECKS) == 9
