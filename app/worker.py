"""
ARQ Worker for Quantsiv MVP
Handles the scanning jobs
"""

import json
import logging
import os
import shutil
import tempfile
from datetime import UTC, datetime
from typing import ClassVar

from arq.connections import RedisSettings

from app.config import get_settings
from app.models import ScanStatus

logger = logging.getLogger(__name__)

# In a real implementation, these would import actual libraries
# For MVP structure, we're defining the worker logic


class ScanWorker:
    """Handles scanning of repositories for quantum-vulnerable cryptography"""

    def __init__(self):
        self.redis = None  # Would be ARQ Redis connection
        self.db = None  # Would be database connection

    async def scan_repository(
        self, job_id: str, installation_id: int, repo_full_name: str, scan_type: str = "both"
    ) -> dict:
        """
        Main scanning function - orchestrates the entire scan process
        """
        scan_id = None
        temp_dir = None

        try:
            # 1. Create scan record in database
            scan_id = await self._create_scan_record(
                installation_id, repo_full_name, scan_type, "manual"
            )

            # 2. Create temporary directory for cloning
            temp_dir = tempfile.mkdtemp(prefix=f"quantsiv_scan_{scan_id}_")
            repo_path = os.path.join(temp_dir, "repo")

            # 3. Get GitHub installation access token
            access_token = await self._get_github_access_token(installation_id)

            # 4. Clone repository
            await self._clone_repository(repo_full_name, access_token, repo_path)

            # 5. Initialize results containers
            findings = []
            tls_results = []
            domains_to_scan = []

            # 6. Run source code scanning (if requested)
            if scan_type in ["source", "both"]:
                source_findings = await self._scan_source_code(repo_path)
                findings.extend(source_findings)

                # 7. Detect domains from config files for TLS scanning
                domains_to_scan = await self._detect_domains_from_config(repo_path)

            # 8. Run TLS scanning (if requested and domains found)
            if scan_type in ["tls", "both"] and domains_to_scan:
                tls_results = await self._scan_tls_domains(domains_to_scan)
                findings.extend(self._tls_results_to_findings(tls_results))

            # 9. Compute risk score
            risk_score = self._compute_risk_score(findings)

            # 10. Generate CBOM
            cbom_json = await self._generate_cbom(findings, tls_results, repo_path)

            # 11. Save results to database
            await self._save_scan_results(scan_id, findings, cbom_json, risk_score, tls_results)

            # 12. Update scan status to completed
            await self._update_scan_status(scan_id, ScanStatus.DONE)

            return {
                "scan_id": scan_id,
                "status": ScanStatus.DONE,
                "findings_count": len(findings),
                "risk_score": risk_score,
            }

        except Exception as e:
            # Update scan status to failed
            if scan_id:
                await self._update_scan_status(scan_id, ScanStatus.FAILED, str(e))
            raise

        finally:
            # 13. Clean up temp files
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    async def _create_scan_record(
        self, installation_id: int, repo_full_name: str, scan_type: str, triggered_by: str
    ) -> int:
        """Create a new scan record and return the scan ID"""
        # In real implementation: INSERT INTO scans ... RETURNING id
        # For MVP structure, we'll return a placeholder
        print(f"Creating scan record for {repo_full_name}")
        return 1  # Placeholder

    async def _get_github_access_token(self, installation_id: int) -> str:
        """Get fresh GitHub installation access token"""
        # In real implementation:
        # 1. Sign JWT with GitHub App private key
        # 2. POST to https://api.github.com/app/installations/{id}/access_tokens
        # 3. Return token
        print(f"Getting GitHub access token for installation {installation_id}")
        return "gho_placeholder_token"  # Placeholder

    async def _clone_repository(
        self, repo_full_name: str, access_token: str, repo_path: str
    ) -> None:
        """Clone repository using gitpython or subprocess"""
        # In real implementation:
        # git clone https://x-access-token:{token}@github.com/{repo}.git {repo_path}
        print(f"Cloning {repo_full_name} to {repo_path}")
        # Placeholder - would actually clone
        os.makedirs(repo_path, exist_ok=True)
        # Create a sample file for testing
        sample_file = os.path.join(repo_path, "sample.py")
        with open(sample_file, "w") as f:  # noqa: ASYNC230 - placeholder; WP4 fixes (A46)
            f.write("""
# Sample file with quantum-vulnerable cryptography for testing
from Crypto.PublicKey import RSA
key = RSA.generate(2048)  # This should be detected as quantum-vulnerable
""")

    async def _scan_source_code(self, repo_path: str) -> list[dict]:
        """Run cbomkit-lib on the repository to find cryptographic assets"""
        # In real implementation:
        # TODO: Actually call cbomkit-lib via subprocess and parse output
        # java -jar /app/bin/cbomkit-lib.jar scan --input {repo_path} --output /tmp/scan/cbom.json --format cyclonedx-json
        # Parse the CycloneDX JSON output
        print(f"Scanning source code in {repo_path}")

        # Placeholder findings for MVP
        return [
            {
                "file_path": "sample.py",
                "line_number": 3,
                "algorithm": "RSA",
                "algorithm_family": "asymmetric",
                "key_size": 2048,
                "quantum_safe": False,
                "severity": "high",
                "confidence": 0.95,
                "context_label": "Key generation",
                "raw_match": "key = RSA.generate(2048)",
            }
        ]

    async def _detect_domains_from_config(self, repo_path: str) -> list[str]:
        """Scan config files for hostnames/domains to check for TLS"""
        # In real implementation:
        # Scan for hostnames in .env, config.yaml, application.properties, .env.example
        print(f"Detecting domains from config files in {repo_path}")
        return ["example.com"]  # Placeholder

    async def _scan_tls_domains(self, domains: list[str]) -> list[dict]:
        """Run TLS scan via sslyze on domains"""
        # In real implementation:
        # Use sslyze Scanner to scan each domain
        # Extract: cert algorithm, key bits, cipher suites, TLS version, expiry
        print(f"Scanning TLS domains: {domains}")

        # Placeholder TLS results
        return [
            {
                "domain": "example.com",
                "cert_algorithm": "RSA",
                "cert_key_bits": 2048,
                "quantum_safe": False,
                "cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
                "tls_version": "TLSv1.2",
                "cert_expiry": "2027-01-01T00:00:00Z",
            }
        ]

    def _tls_results_to_findings(self, tls_results: list[dict]) -> list[dict]:
        """Convert TLS scan results to finding format"""
        findings = []
        for tls_result in tls_results:
            if not tls_result.get("quantum_safe", True):
                findings.append(
                    {
                        "file_path": None,  # TLS findings don't have file paths
                        "line_number": None,
                        "algorithm": tls_result.get("cert_algorithm"),
                        "algorithm_family": "asymmetric",  # or 'kex' for key exchange
                        "key_size": tls_result.get("cert_key_bits"),
                        "quantum_safe": False,
                        "severity": "medium",  # TLS findings are typically medium severity
                        "confidence": 0.9,
                        "context_label": "TLS handshake",
                        "raw_match": f"{tls_result.get('domain')}:{tls_result.get('cert_algorithm')}-{tls_result.get('cert_key_bits')}",
                    }
                )
        return findings

    def _compute_risk_score(self, findings: list[dict]) -> int:
        """Compute risk score (0-100) based on findings"""
        # Based on spec:
        # base = 0
        # base += critical_count * 25   (cap at 50)
        # base += high_count * 10        (cap at 30)
        # base += medium_count * 5       (cap at 20)
        # risk_score = min(100, base)

        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        medium_count = sum(1 for f in findings if f.get("severity") == "medium")

        base = 0
        base += min(critical_count * 25, 50)
        base += min(high_count * 10, 30)
        base += min(medium_count * 5, 20)

        return min(100, base)

    async def _generate_cbom(
        self, findings: list[dict], tls_results: list[dict], repo_path: str
    ) -> str:
        """Generate CycloneDX 1.6 CBOM JSON"""
        # In real implementation: use cyclonedx-python-lib to assemble CBOM
        print("Generating CBOM")

        # Placeholder CBOM
        cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:placeholder",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": [
                    {"vendor": "Quantsiv", "name": "quantum-crypto-scanner", "version": "0.1.0"}
                ],
            },
            "components": [],
            "vulnerabilities": [],
        }

        # Add findings as vulnerabilities in CBOM
        for finding in findings:
            vuln = {
                "id": f"VULN-{finding.get('file_path', 'TLS')}-{finding.get('line_number', 0)}",
                "source": {"name": "qvscanner", "url": "https://quantsiv.io"},
                "ratings": [
                    {
                        "method": "CVSSv31",
                        "score": 9.0
                        if finding.get("severity") == "critical"
                        else 7.0
                        if finding.get("severity") == "high"
                        else 5.0,
                        "severity": finding.get("severity").upper(),
                    }
                ],
                "description": f"Quantum-vulnerable {finding.get('algorithm')} algorithm detected",
                "references": [
                    {
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-XXXX",
                        "source": {"name": "NIST NVD"},
                    }
                ],
            }
            cbom["vulnerabilities"].append(vuln)

        return json.dumps(cbom, indent=2)

    async def _save_scan_results(
        self,
        scan_id: int,
        findings: list[dict],
        cbom_json: str,
        risk_score: int,
        tls_results: list[dict],
    ) -> None:
        """Save scan results to database"""
        # In real implementation:
        # INSERT INTO findings, cbom_snapshots, tls_scans
        print(f"Saving scan results for scan {scan_id}")
        print(f"  Findings: {len(findings)}")
        print(f"  Risk score: {risk_score}")
        print(f"  TLS results: {len(tls_results)}")

    async def _update_scan_status(
        self, scan_id: int, status: ScanStatus, error_message: str | None = None
    ) -> None:
        """Update scan status in database"""
        # In real implementation: UPDATE scans SET status=?, error_message=?, completed_at=?
        print(f"Updating scan {scan_id} status to {status}")
        if error_message:
            print(f"  Error: {error_message}")


# ARQ jobs (A50). Placeholders until WP4 wires them to ScanWorker and the database: they
# accept the planned arguments, log, and do nothing else.
async def scan_repository(
    ctx: dict, installation_id: int, repo_full_name: str, triggered_by: str = "manual"
) -> None:
    logger.info("scan_repository: not implemented until WP4")


async def handle_github_event(ctx: dict, event: str, payload: dict) -> str:
    """Process a verified GitHub webhook (A12, A13). Returns what was done, for the job result.

    Storing installations needs the data layer (WP4); until then installation events are logged
    by ID only (no account names at INFO, A25).
    """
    action = payload.get("action")
    if event == "installation":
        installation = payload.get("installation") or {}
        account = installation.get("account") or {}  # not payload["account"] (A12)
        logger.info("installation %s: %s", action, installation.get("id"))
        logger.debug("installation account %s (%s)", account.get("login"), account.get("type"))
        return f"installation-{action}"
    if event == "push":
        repo = payload.get("repository") or {}
        if payload.get("deleted"):
            return "ignored-deleted-branch"
        if not repo.get("default_branch") or payload.get("ref") != (
            f"refs/heads/{repo['default_branch']}"
        ):
            return "ignored-non-default-ref"  # tags, other and nested branches (A13)
        await ctx["redis"].enqueue_job(
            "scan_repository",
            payload["installation"]["id"],
            repo["full_name"],
            triggered_by="push",
        )
        return "scan-queued"
    return f"ignored-{event}"


async def delete_account(ctx: dict, user_id: int) -> None:
    logger.info("delete_account: not implemented until WP8")


class WorkerSettings:
    functions: ClassVar[list] = [scan_repository, handle_github_event, delete_account]
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = 600
    max_jobs = 2
    keep_result = 3600
