"""
Unit tests for the scheduling module.

Tests the ScanScheduler, schedule expressions, and scan history components.
"""

import tempfile
from datetime import datetime, timedelta

import pytest

from stance.models.finding import Finding, FindingCollection, FindingStatus, FindingType, Severity
from stance.scheduling.scheduler import (
    CronExpression,
    RateExpression,
    ScanJob,
    ScanResult,
    ScanScheduler,
    ScheduleType,
    parse_schedule,
)
from stance.scheduling.history import (
    DiffType,
    ScanComparison,
    ScanDiff,
    ScanHistoryEntry,
    ScanHistoryManager,
)


# =============================================================================
# Schedule Expression Tests
# =============================================================================


class TestCronExpression:
    """Tests for CronExpression class."""

    def test_create_basic_cron(self):
        """Test creating a basic cron expression."""
        cron = CronExpression(expression="0 * * * *")
        assert cron.expression == "0 * * * *"
        assert cron.get_schedule_type() == ScheduleType.CRON

    def test_create_aws_style_cron(self):
        """Test creating an AWS-style cron expression."""
        cron = CronExpression(expression="cron(0 12 * * ? *)")
        assert cron.get_schedule_type() == ScheduleType.CRON

    def test_cron_matches_minute(self):
        """Test cron matching specific minute."""
        cron = CronExpression(expression="30 * * * *")
        dt_match = datetime(2024, 1, 15, 10, 30)
        dt_no_match = datetime(2024, 1, 15, 10, 15)
        assert cron.matches(dt_match)
        assert not cron.matches(dt_no_match)

    def test_cron_matches_hour(self):
        """Test cron matching specific hour."""
        cron = CronExpression(expression="0 12 * * *")
        dt_match = datetime(2024, 1, 15, 12, 0)
        dt_no_match = datetime(2024, 1, 15, 10, 0)
        assert cron.matches(dt_match)
        assert not cron.matches(dt_no_match)

    def test_cron_matches_wildcard(self):
        """Test cron with all wildcards."""
        cron = CronExpression(expression="* * * * *")
        assert cron.matches(datetime(2024, 1, 15, 10, 30))
        assert cron.matches(datetime(2024, 6, 1, 0, 0))

    def test_cron_matches_step_values(self):
        """Test cron with step values."""
        cron = CronExpression(expression="*/15 * * * *")
        assert cron.matches(datetime(2024, 1, 15, 10, 0))
        assert cron.matches(datetime(2024, 1, 15, 10, 15))
        assert cron.matches(datetime(2024, 1, 15, 10, 30))
        assert cron.matches(datetime(2024, 1, 15, 10, 45))
        assert not cron.matches(datetime(2024, 1, 15, 10, 10))

    def test_cron_matches_range(self):
        """Test cron with range values."""
        cron = CronExpression(expression="0 9-17 * * *")
        assert cron.matches(datetime(2024, 1, 15, 9, 0))
        assert cron.matches(datetime(2024, 1, 15, 12, 0))
        assert cron.matches(datetime(2024, 1, 15, 17, 0))
        assert not cron.matches(datetime(2024, 1, 15, 8, 0))
        assert not cron.matches(datetime(2024, 1, 15, 18, 0))

    def test_cron_get_next_run(self):
        """Test getting next run time."""
        cron = CronExpression(expression="0 12 * * *")
        after = datetime(2024, 1, 15, 10, 0)
        next_run = cron.get_next_run(after)
        assert next_run.hour == 12
        assert next_run.minute == 0

    def test_invalid_cron_expression(self):
        """Test invalid cron expression raises error."""
        with pytest.raises(ValueError):
            CronExpression(expression="invalid")

    def test_cron_comma_separated(self):
        """Test cron with comma-separated values."""
        cron = CronExpression(expression="0,30 * * * *")
        assert cron.matches(datetime(2024, 1, 15, 10, 0))
        assert cron.matches(datetime(2024, 1, 15, 10, 30))
        assert not cron.matches(datetime(2024, 1, 15, 10, 15))


class TestRateExpression:
    """Tests for RateExpression class."""

    def test_create_rate_minutes(self):
        """Test creating a rate expression with minutes."""
        rate = RateExpression(expression="rate(5 minutes)")
        assert rate.interval == timedelta(minutes=5)
        assert rate.get_schedule_type() == ScheduleType.RATE

    def test_create_rate_hours(self):
        """Test creating a rate expression with hours."""
        rate = RateExpression(expression="rate(1 hour)")
        assert rate.interval == timedelta(hours=1)

    def test_create_rate_days(self):
        """Test creating a rate expression with days."""
        rate = RateExpression(expression="rate(1 day)")
        assert rate.interval == timedelta(days=1)

    def test_rate_without_wrapper(self):
        """Test rate expression without rate() wrapper."""
        rate = RateExpression(expression="30 minutes")
        assert rate.interval == timedelta(minutes=30)

    def test_rate_get_next_run(self):
        """Test getting next run time."""
        rate = RateExpression(expression="rate(1 hour)")
        after = datetime(2024, 1, 15, 10, 0)
        next_run = rate.get_next_run(after)
        assert next_run == after + timedelta(hours=1)

    def test_invalid_rate_expression(self):
        """Test invalid rate expression raises error."""
        with pytest.raises(ValueError):
            RateExpression(expression="invalid")


class TestParseSchedule:
    """Tests for parse_schedule function."""

    def test_parse_cron(self):
        """Test parsing cron expression."""
        schedule = parse_schedule("0 12 * * *")
        assert isinstance(schedule, CronExpression)

    def test_parse_rate(self):
        """Test parsing rate expression."""
        schedule = parse_schedule("rate(5 minutes)")
        assert isinstance(schedule, RateExpression)

    def test_parse_rate_simple(self):
        """Test parsing simple rate expression."""
        schedule = parse_schedule("5 minutes")
        assert isinstance(schedule, RateExpression)


# =============================================================================
# Scan Result Tests
# =============================================================================


class TestScanResult:
    """Tests for ScanResult class."""

    def test_create_result(self):
        """Test creating a scan result."""
        result = ScanResult(
            job_id="job-1",
            scan_id="scan-1",
            started_at=datetime(2024, 1, 15, 10, 0),
            completed_at=datetime(2024, 1, 15, 10, 5),
            success=True,
            assets_scanned=100,
            findings_count=10,
        )
        assert result.job_id == "job-1"
        assert result.success
        assert result.duration == timedelta(minutes=5)

    def test_result_duration_incomplete(self):
        """Test duration when scan not complete."""
        result = ScanResult(
            job_id="job-1",
            scan_id="scan-1",
            started_at=datetime(2024, 1, 15, 10, 0),
        )
        assert result.duration is None

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = ScanResult(
            job_id="job-1",
            scan_id="scan-1",
            started_at=datetime(2024, 1, 15, 10, 0),
            completed_at=datetime(2024, 1, 15, 10, 5),
        )
        data = result.to_dict()
        assert data["job_id"] == "job-1"
        assert data["scan_id"] == "scan-1"
        assert data["duration_seconds"] == 300

    def test_result_from_dict(self):
        """Test creating result from dictionary."""
        data = {
            "job_id": "job-1",
            "scan_id": "scan-1",
            "started_at": "2024-01-15T10:00:00",
            "completed_at": "2024-01-15T10:05:00",
            "success": True,
        }
        result = ScanResult.from_dict(data)
        assert result.job_id == "job-1"
        assert result.success


# =============================================================================
# Scan Job Tests
# =============================================================================


class TestScanJob:
    """Tests for ScanJob class."""

    def test_create_job(self):
        """Test creating a scan job."""
        schedule = CronExpression(expression="0 12 * * *")
        job = ScanJob(
            id="job-1",
            name="Daily Scan",
            schedule=schedule,
            config_name="default",
        )
        assert job.id == "job-1"
        assert job.name == "Daily Scan"
        assert job.enabled
        assert job.next_run is not None

    def test_job_should_run(self):
        """Test checking if job should run."""
        schedule = RateExpression(expression="rate(1 hour)")
        job = ScanJob(
            id="job-1",
            name="Test",
            schedule=schedule,
            next_run=datetime(2024, 1, 15, 10, 0),
        )
        assert job.should_run(datetime(2024, 1, 15, 10, 0))
        assert job.should_run(datetime(2024, 1, 15, 11, 0))
        assert not job.should_run(datetime(2024, 1, 15, 9, 0))

    def test_job_should_run_disabled(self):
        """Test disabled job should not run."""
        schedule = RateExpression(expression="rate(1 hour)")
        job = ScanJob(
            id="job-1",
            name="Test",
            schedule=schedule,
            enabled=False,
        )
        assert not job.should_run()

    def test_job_mark_run(self):
        """Test marking job as run."""
        schedule = RateExpression(expression="rate(1 hour)")
        job = ScanJob(
            id="job-1",
            name="Test",
            schedule=schedule,
        )
        result = ScanResult(
            job_id="job-1",
            scan_id="scan-1",
            started_at=datetime(2024, 1, 15, 10, 0),
            completed_at=datetime(2024, 1, 15, 10, 5),
        )
        job.mark_run(result)
        assert job.last_run == result.started_at
        assert job.run_count == 1
        assert job.last_result == result

    def test_job_to_dict(self):
        """Test converting job to dictionary."""
        schedule = CronExpression(expression="0 12 * * *")
        job = ScanJob(
            id="job-1",
            name="Test",
            schedule=schedule,
        )
        data = job.to_dict()
        assert data["id"] == "job-1"
        assert data["schedule_type"] == "cron"
        assert data["schedule_expression"] == "0 12 * * *"

    def test_job_from_dict(self):
        """Test creating job from dictionary."""
        data = {
            "id": "job-1",
            "name": "Test",
            "schedule_type": "rate",
            "schedule_expression": "rate(1 hour)",
            "config_name": "default",
            "enabled": True,
        }
        job = ScanJob.from_dict(data)
        assert job.id == "job-1"
        assert isinstance(job.schedule, RateExpression)


# =============================================================================
# Scan Scheduler Tests
# =============================================================================


class TestScanScheduler:
    """Tests for ScanScheduler class."""

    def test_scheduler_initialization(self):
        """Test scheduler initialization."""
        scheduler = ScanScheduler()
        assert not scheduler.is_running()
        assert len(scheduler.get_jobs()) == 0

    def test_add_job(self):
        """Test adding a job."""
        scheduler = ScanScheduler()
        job = scheduler.add_job(
            name="Test Job",
            schedule="rate(1 hour)",
            config_name="default",
        )
        assert job.name == "Test Job"
        assert len(scheduler.get_jobs()) == 1

    def test_add_job_with_cron(self):
        """Test adding a job with cron schedule."""
        scheduler = ScanScheduler()
        job = scheduler.add_job(
            name="Daily Scan",
            schedule="0 12 * * *",
        )
        assert isinstance(job.schedule, CronExpression)

    def test_add_job_with_expression(self):
        """Test adding a job with schedule expression object."""
        scheduler = ScanScheduler()
        schedule = RateExpression(expression="rate(30 minutes)")
        job = scheduler.add_job(
            name="Frequent Scan",
            schedule=schedule,
        )
        assert job.schedule == schedule

    def test_remove_job(self):
        """Test removing a job."""
        scheduler = ScanScheduler()
        job = scheduler.add_job(name="Test", schedule="rate(1 hour)")
        assert scheduler.remove_job(job.id)
        assert len(scheduler.get_jobs()) == 0

    def test_remove_nonexistent_job(self):
        """Test removing a job that doesn't exist."""
        scheduler = ScanScheduler()
        assert not scheduler.remove_job("nonexistent")

    def test_get_job(self):
        """Test getting a job by ID."""
        scheduler = ScanScheduler()
        job = scheduler.add_job(name="Test", schedule="rate(1 hour)")
        retrieved = scheduler.get_job(job.id)
        assert retrieved == job

    def test_get_enabled_jobs(self):
        """Test getting enabled jobs."""
        scheduler = ScanScheduler()
        scheduler.add_job(name="Enabled", schedule="rate(1 hour)", enabled=True)
        scheduler.add_job(name="Disabled", schedule="rate(1 hour)", enabled=False)
        enabled = scheduler.get_enabled_jobs()
        assert len(enabled) == 1
        assert enabled[0].name == "Enabled"

    def test_enable_disable_job(self):
        """Test enabling and disabling a job."""
        scheduler = ScanScheduler()
        job = scheduler.add_job(name="Test", schedule="rate(1 hour)", enabled=False)
        assert not job.enabled
        scheduler.enable_job(job.id)
        assert job.enabled
        scheduler.disable_job(job.id)
        assert not job.enabled

    def test_get_pending_jobs(self):
        """Test getting pending jobs."""
        scheduler = ScanScheduler()
        past_time = datetime.utcnow() - timedelta(hours=1)
        future_time = datetime.utcnow() + timedelta(hours=1)

        job1 = scheduler.add_job(name="Due", schedule="rate(1 hour)")
        job1.next_run = past_time

        job2 = scheduler.add_job(name="Not Due", schedule="rate(1 hour)")
        job2.next_run = future_time

        pending = scheduler.get_pending_jobs()
        assert len(pending) == 1
        assert pending[0].name == "Due"

    def test_run_job_now(self):
        """Test running a job immediately."""
        results = []

        def executor(config_name: str) -> ScanResult:
            result = ScanResult(
                job_id="",
                scan_id="test",
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                assets_scanned=10,
            )
            results.append(result)
            return result

        scheduler = ScanScheduler(scan_executor=executor)
        job = scheduler.add_job(name="Test", schedule="rate(1 hour)")
        result = scheduler.run_job_now(job.id)

        assert result is not None
        assert len(results) == 1
        assert job.run_count == 1

    def test_callback(self):
        """Test job completion callback."""
        callback_results = []

        def callback(job: ScanJob, result: ScanResult):
            callback_results.append((job.name, result.success))

        scheduler = ScanScheduler()
        scheduler.add_callback(callback)
        job = scheduler.add_job(name="Test", schedule="rate(1 hour)")
        scheduler.run_job_now(job.id)

        assert len(callback_results) == 1
        assert callback_results[0] == ("Test", True)

    def test_get_status(self):
        """Test getting scheduler status."""
        scheduler = ScanScheduler()
        scheduler.add_job(name="Job1", schedule="rate(1 hour)")
        scheduler.add_job(name="Job2", schedule="rate(2 hours)", enabled=False)

        status = scheduler.get_status()
        assert status["total_jobs"] == 2
        assert status["enabled_jobs"] == 1
        assert not status["running"]

    def test_scheduler_to_from_dict(self):
        """Test serializing and deserializing scheduler."""
        scheduler = ScanScheduler()
        scheduler.add_job(name="Test", schedule="rate(1 hour)")

        data = scheduler.to_dict()
        restored = ScanScheduler.from_dict(data)

        assert len(restored.get_jobs()) == 1
        assert restored.get_jobs()[0].name == "Test"


# =============================================================================
# Scan History Tests
# =============================================================================


@pytest.fixture
def history_manager():
    """Create a temporary history manager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield ScanHistoryManager(storage_path=tmpdir)


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return FindingCollection([
        Finding(
            id="finding-1",
            asset_id="asset-1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Finding 1",
            description="Test finding 1",
        ),
        Finding(
            id="finding-2",
            asset_id="asset-2",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            title="Finding 2",
            description="Test finding 2",
        ),
        Finding(
            id="finding-3",
            asset_id="asset-3",
            finding_type=FindingType.VULNERABILITY,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="Finding 3",
            description="Test finding 3",
        ),
    ])


class TestScanHistoryEntry:
    """Tests for ScanHistoryEntry class."""

    def test_create_entry(self):
        """Test creating a history entry."""
        entry = ScanHistoryEntry(
            scan_id="scan-1",
            timestamp=datetime(2024, 1, 15, 10, 0),
            config_name="default",
            assets_scanned=100,
            findings_total=10,
        )
        assert entry.scan_id == "scan-1"
        assert entry.assets_scanned == 100

    def test_entry_to_dict(self):
        """Test converting entry to dictionary."""
        entry = ScanHistoryEntry(
            scan_id="scan-1",
            timestamp=datetime(2024, 1, 15, 10, 0),
            findings_by_severity={"critical": 1, "high": 5},
        )
        data = entry.to_dict()
        assert data["scan_id"] == "scan-1"
        assert data["findings_by_severity"]["critical"] == 1

    def test_entry_from_dict(self):
        """Test creating entry from dictionary."""
        data = {
            "scan_id": "scan-1",
            "timestamp": "2024-01-15T10:00:00",
            "config_name": "default",
            "assets_scanned": 50,
        }
        entry = ScanHistoryEntry.from_dict(data)
        assert entry.scan_id == "scan-1"
        assert entry.assets_scanned == 50


class TestScanDiff:
    """Tests for ScanDiff class."""

    def test_create_diff(self):
        """Test creating a scan diff."""
        finding = Finding(
            id="finding-1",
            asset_id="asset-1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Test",
            description="Test",
        )
        diff = ScanDiff(
            finding_id="finding-1",
            diff_type=DiffType.NEW,
            finding=finding,
        )
        assert diff.diff_type == DiffType.NEW
        assert diff.finding is not None

    def test_diff_to_dict(self):
        """Test converting diff to dictionary."""
        diff = ScanDiff(
            finding_id="finding-1",
            diff_type=DiffType.SEVERITY_CHANGED,
            previous_severity=Severity.MEDIUM,
            current_severity=Severity.HIGH,
        )
        data = diff.to_dict()
        assert data["diff_type"] == "severity_changed"
        assert data["previous_severity"] == "medium"
        assert data["current_severity"] == "high"


class TestScanComparison:
    """Tests for ScanComparison class."""

    def test_create_comparison(self):
        """Test creating a comparison."""
        comparison = ScanComparison(
            baseline_scan_id="scan-1",
            current_scan_id="scan-2",
            baseline_timestamp=datetime(2024, 1, 15, 10, 0),
            current_timestamp=datetime(2024, 1, 16, 10, 0),
        )
        assert comparison.baseline_scan_id == "scan-1"
        assert not comparison.has_changes

    def test_comparison_with_changes(self):
        """Test comparison with changes."""
        comparison = ScanComparison(
            baseline_scan_id="scan-1",
            current_scan_id="scan-2",
            baseline_timestamp=datetime(2024, 1, 15, 10, 0),
            current_timestamp=datetime(2024, 1, 16, 10, 0),
            new_findings=[ScanDiff("f1", DiffType.NEW)],
        )
        assert comparison.has_changes
        assert comparison.total_new == 1

    def test_improvement_ratio(self):
        """Test improvement ratio calculation."""
        comparison = ScanComparison(
            baseline_scan_id="scan-1",
            current_scan_id="scan-2",
            baseline_timestamp=datetime(2024, 1, 15, 10, 0),
            current_timestamp=datetime(2024, 1, 16, 10, 0),
            new_findings=[ScanDiff("f1", DiffType.NEW)],
            resolved_findings=[
                ScanDiff("f2", DiffType.RESOLVED),
                ScanDiff("f3", DiffType.RESOLVED),
                ScanDiff("f4", DiffType.RESOLVED),
            ],
        )
        # 3 resolved, 1 new = (3-1)/4 = 0.5 improvement
        assert comparison.improvement_ratio == 0.5


class TestScanHistoryManager:
    """Tests for ScanHistoryManager class."""

    def test_record_scan(self, history_manager, sample_findings):
        """Test recording a scan."""
        entry = history_manager.record_scan(
            scan_id="scan-1",
            findings=sample_findings,
            assets_scanned=100,
        )
        assert entry.scan_id == "scan-1"
        assert entry.findings_total == 3

    def test_get_history(self, history_manager, sample_findings):
        """Test getting scan history."""
        history_manager.record_scan(scan_id="scan-1", findings=sample_findings)
        history_manager.record_scan(scan_id="scan-2", findings=sample_findings)

        history = history_manager.get_history()
        assert len(history) == 2

    def test_get_history_with_limit(self, history_manager, sample_findings):
        """Test getting limited history."""
        for i in range(5):
            history_manager.record_scan(scan_id=f"scan-{i}", findings=sample_findings)

        history = history_manager.get_history(limit=3)
        assert len(history) == 3

    def test_get_latest(self, history_manager, sample_findings):
        """Test getting latest scan."""
        history_manager.record_scan(scan_id="scan-1", findings=sample_findings)
        history_manager.record_scan(scan_id="scan-2", findings=sample_findings)

        latest = history_manager.get_latest()
        assert latest.scan_id == "scan-2"

    def test_get_findings(self, history_manager, sample_findings):
        """Test retrieving findings for a scan."""
        history_manager.record_scan(scan_id="scan-1", findings=sample_findings)

        retrieved = history_manager.get_findings("scan-1")
        assert len(retrieved) == 3

    def test_compare_scans(self, history_manager):
        """Test comparing two scans."""
        findings1 = FindingCollection([
            Finding(
                id="f1", asset_id="a1", finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH, status=FindingStatus.OPEN,
                title="Finding 1", description="",
            ),
            Finding(
                id="f2", asset_id="a2", finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.MEDIUM, status=FindingStatus.OPEN,
                title="Finding 2", description="",
            ),
        ])
        findings2 = FindingCollection([
            Finding(
                id="f1", asset_id="a1", finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH, status=FindingStatus.OPEN,
                title="Finding 1", description="",
            ),
            Finding(
                id="f3", asset_id="a3", finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.LOW, status=FindingStatus.OPEN,
                title="Finding 3", description="",
            ),
        ])

        history_manager.record_scan(scan_id="scan-1", findings=findings1)
        history_manager.record_scan(scan_id="scan-2", findings=findings2)

        comparison = history_manager.compare_scans("scan-1", "scan-2")

        assert comparison is not None
        assert len(comparison.new_findings) == 1  # f3 is new
        assert len(comparison.resolved_findings) == 1  # f2 is resolved
        assert len(comparison.unchanged_findings) == 1  # f1 unchanged

    def test_get_trend(self, history_manager, sample_findings):
        """Test getting trend data."""
        for i in range(3):
            history_manager.record_scan(scan_id=f"scan-{i}", findings=sample_findings)

        trend = history_manager.get_trend(days=7)
        assert len(trend) == 3
        assert all("findings_total" in t for t in trend)

    def test_cleanup_old_entries(self, history_manager, sample_findings):
        """Test cleaning up old entries."""
        # Record a scan with old timestamp
        entry = history_manager.record_scan(scan_id="old-scan", findings=sample_findings)
        # Manually set old timestamp
        entries = history_manager._load_all_entries()
        entries[0].timestamp = datetime(2020, 1, 1)
        history_manager._save_all_entries(entries)

        # Record a recent scan
        history_manager.record_scan(scan_id="new-scan", findings=sample_findings)

        removed = history_manager.cleanup_old_entries(retention_days=30)
        assert removed == 1

        history = history_manager.get_history()
        assert len(history) == 1
        assert history[0].scan_id == "new-scan"
