import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import httpx
from fastapi import HTTPException, status

from app.config import settings
from app.models.schemas import ScanResponse
from app.core.logging import logger

class ScanRepository:
    """
    Persistent scan metadata repository for MALGUARD AI.
    Integrates with Supabase PostgreSQL via PostgREST API with Row Level Security (RLS).
    Maintains an in-memory session cache for resilient fallback during network or DB outages.
    STRICT SECURITY RULE: Never stores uploaded binary payloads or file buffers.
    """

    def __init__(self):
        self.supabase_url = settings.SUPABASE_URL.rstrip("/")
        self.anon_key = settings.SUPABASE_ANON_KEY
        # In-memory session store: user_id -> List[Dict]
        self._fallback_store: Dict[str, List[Dict[str, Any]]] = {}

    def _format_scan_record(self, scan: ScanResponse, user_id: str) -> Dict[str, Any]:
        """Maps ScanResponse to the database schema for public.scans."""
        return {
            "id": scan.scan_id,
            "user_id": user_id,
            "file_name": scan.file_name,
            "file_size_bytes": scan.file_size_bytes,
            "formatted_size": scan.formatted_size,
            "sha256": scan.hashes.get("sha256", ""),
            "sha1": scan.hashes.get("sha1", ""),
            "md5": scan.hashes.get("md5", ""),
            "verdict": scan.verdict.value,
            "verdict_reasons": scan.verdict_reasons,
            "pe_summary": {
                "status": scan.pe_analysis.status,
                "machine": scan.pe_analysis.headers.machine,
                "subsystem": scan.pe_analysis.headers.subsystem,
                "number_of_sections": scan.pe_analysis.headers.number_of_sections,
                "file_entropy": scan.pe_analysis.file_entropy,
                "imported_dlls_count": scan.pe_analysis.imported_dlls_count,
                "total_imports_count": scan.pe_analysis.total_imports_count,
                "exported_functions_count": scan.pe_analysis.exported_functions_count,
                "suspicious_indicators_count": len(scan.pe_analysis.suspicious_indicators),
            },
            "clamav_status": scan.clamav.status,
            "clamav_available": scan.clamav.available,
            "clamav_matched": scan.clamav.matched,
            "clamav_signature": scan.clamav.signature_name,
            "clamav_message": scan.clamav.message,
            "ml_status": scan.ml_inference.status,
            "ml_available": scan.ml_inference.available,
            "ml_prediction": scan.ml_inference.prediction,
            "ml_confidence_score": scan.ml_inference.confidence_score,
            "ml_message": scan.ml_inference.message,
            "created_at": scan.timestamp.isoformat(),
        }

    async def save_scan(self, scan: ScanResponse, user_id: str, raw_token: Optional[str] = None) -> bool:
        """
        Saves scan record to Supabase PostgreSQL with user ownership and RLS.
        When database persistence is expected (ALLOW_IN_MEMORY_FALLBACK=False),
        failures are explicitly raised rather than silently falling back to RAM.
        """
        record = self._format_scan_record(scan, user_id)

        # 1. Validate Supabase credentials
        if not self.supabase_url or not self.anon_key:
            if not settings.ALLOW_IN_MEMORY_FALLBACK:
                logger.error("Supabase credentials not configured while database persistence is required.")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database persistence configuration is missing on server."
                )
            # Offline test fallback
            logger.info("Supabase credentials not set; record saved to session cache (fallback mode).")
            if user_id not in self._fallback_store:
                self._fallback_store[user_id] = []
            self._fallback_store[user_id].insert(0, record)
            return True

        # Use client JWT if valid format (3 parts), otherwise use service anon key
        auth_bearer = raw_token if (raw_token and "." in raw_token) else self.anon_key
        headers = {
            "apikey": self.anon_key,
            "Authorization": f"Bearer {auth_bearer}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }

        url = f"{self.supabase_url}/rest/v1/scans"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=record, headers=headers)
                if resp.status_code in [200, 201]:
                    logger.info(f"Persisted scan {scan.scan_id} to Supabase PostgreSQL for user {user_id}")
                    # Cache successful record for rapid session reads
                    if user_id not in self._fallback_store:
                        self._fallback_store[user_id] = []
                    self._fallback_store[user_id].insert(0, record)
                    return True
                else:
                    logger.error(
                        f"Supabase persistence error ({resp.status_code}): {resp.text[:200]}"
                    )
                    if not settings.ALLOW_IN_MEMORY_FALLBACK:
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"Database persistence failed (Supabase returned HTTP {resp.status_code}): {resp.text[:200]}"
                        )
                    # Fallback mode (testing only)
                    if user_id not in self._fallback_store:
                        self._fallback_store[user_id] = []
                    self._fallback_store[user_id].insert(0, record)
                    return True
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Could not reach Supabase REST API: {e}")
            if not settings.ALLOW_IN_MEMORY_FALLBACK:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Database connection error: Unable to reach Supabase REST API ({str(e)})"
                )
            if user_id not in self._fallback_store:
                self._fallback_store[user_id] = []
            self._fallback_store[user_id].insert(0, record)
            return True

    async def get_user_scans(
        self,
        user_id: str,
        raw_token: Optional[str] = None,
        limit: int = 50,
        search: Optional[str] = None,
        verdict: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves scan history strictly owned by user_id with search/filter capabilities.
        Enforces tenant isolation: users cannot see records owned by others.
        Disables silent in-memory fallback when database persistence is expected.
        """
        remote_records: Optional[List[Dict[str, Any]]] = None

        if self.supabase_url and self.anon_key:
            auth_bearer = raw_token if (raw_token and "." in raw_token) else self.anon_key
            headers = {
                "apikey": self.anon_key,
                "Authorization": f"Bearer {auth_bearer}",
                "Accept": "application/json"
            }
            # Strictly filter by user_id
            params = {
                "user_id": f"eq.{user_id}",
                "order": "created_at.desc",
                "limit": str(limit)
            }
            if verdict:
                params["verdict"] = f"eq.{verdict.upper()}"
            if search:
                # PostgREST ilike on file_name or sha256
                params["or"] = f"(file_name.ilike.*{search}*,sha256.ilike.*{search}*)"

            url = f"{self.supabase_url}/rest/v1/scans"
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(url, headers=headers, params=params)
                    if resp.status_code == 200:
                        remote_records = resp.json()
                    else:
                        logger.error(f"Supabase query failed ({resp.status_code}): {resp.text[:200]}")
                        if not settings.ALLOW_IN_MEMORY_FALLBACK:
                            raise HTTPException(
                                status_code=status.HTTP_502_BAD_GATEWAY,
                                detail=f"Database query error (Supabase returned HTTP {resp.status_code}): {resp.text[:200]}"
                            )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to query Supabase REST API: {e}")
                if not settings.ALLOW_IN_MEMORY_FALLBACK:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Database query error: Unable to contact Supabase REST API ({str(e)})"
                    )

        # If remote returned records, use them
        if remote_records is not None and len(remote_records) > 0:
            return remote_records

        # If fallback is explicitly permitted (e.g. preview / demo / offline testing), check session fallback store
        if settings.ALLOW_IN_MEMORY_FALLBACK and user_id in self._fallback_store:
            user_records = self._fallback_store.get(user_id, [])
            filtered = user_records

            if verdict:
                v_upper = verdict.upper()
                filtered = [r for r in filtered if r.get("verdict") == v_upper]

            if search:
                s_lower = search.lower()
                filtered = [
                    r for r in filtered
                    if s_lower in r.get("file_name", "").lower() or s_lower in r.get("sha256", "").lower()
                ]

            return filtered[:limit]

        if remote_records is not None:
            return remote_records

        return []

    async def get_scan_by_id(
        self,
        user_id: str,
        scan_id: str,
        raw_token: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves a single scan by scan_id, strictly enforcing user ownership.
        Optimized single-row query to Supabase PostgreSQL without loading large scan lists.
        """
        # Check in-memory store first if fallback has it
        if user_id in self._fallback_store:
            for s in self._fallback_store[user_id]:
                if s.get("id") == scan_id:
                    return s

        if self.supabase_url and self.anon_key:
            auth_bearer = raw_token if (raw_token and "." in raw_token) else self.anon_key
            headers = {
                "apikey": self.anon_key,
                "Authorization": f"Bearer {auth_bearer}",
                "Accept": "application/json"
            }
            params = {
                "id": f"eq.{scan_id}",
                "user_id": f"eq.{user_id}",
                "limit": "1"
            }
            url = f"{self.supabase_url}/rest/v1/scans"
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.get(url, headers=headers, params=params)
                    if resp.status_code == 200:
                        records = resp.json()
                        if records and isinstance(records, list) and len(records) > 0:
                            return records[0]
                        return None
                    else:
                        logger.warning(f"Supabase single scan lookup ({resp.status_code}): {resp.text[:100]}")
                        if not settings.ALLOW_IN_MEMORY_FALLBACK:
                            raise HTTPException(
                                status_code=status.HTTP_502_BAD_GATEWAY,
                                detail=f"Database query error: Supabase returned HTTP {resp.status_code}"
                            )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to query scan {scan_id} from Supabase: {e}")
                if not settings.ALLOW_IN_MEMORY_FALLBACK:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Database query error: Unable to contact Supabase REST API ({str(e)})"
                    )

        # Fallback store if permitted
        if settings.ALLOW_IN_MEMORY_FALLBACK:
            for s in self._fallback_store.get(user_id, []):
                if s.get("id") == scan_id:
                    return s

        return None

    async def get_dashboard_metrics(
        self,
        user_id: str,
        raw_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Computes authenticated user telemetry for the security dashboard:
        Total scans, threats detected, clean files, suspicious files,
        and real activity breakdowns.
        """
        scans = await self.get_user_scans(user_id, raw_token, limit=200)

        total_scans = len(scans)
        threats_detected = sum(1 for s in scans if s.get("verdict") == "MALICIOUS")
        suspicious_files = sum(1 for s in scans if s.get("verdict") == "SUSPICIOUS")
        clean_files = sum(1 for s in scans if s.get("verdict") == "NO_THREAT_DETECTED")
        inconclusive_files = sum(1 for s in scans if s.get("verdict") == "INCONCLUSIVE")

        # Format recent scans for table (top 10)
        recent_scans = []
        for s in scans[:10]:
            recent_scans.append({
                "id": s.get("id", ""),
                "fileName": s.get("file_name", "unknown.bin"),
                "fileSize": s.get("formatted_size", "0 B"),
                "sha256": s.get("sha256", ""),
                "verdict": s.get("verdict", "INCONCLUSIVE"),
                "scannedAt": s.get("created_at", ""),
                "type": s.get("pe_summary", {}).get("machine", "PE Binary"),
                "clamav": s.get("clamav_status", "unavailable"),
                "mlPrediction": s.get("ml_prediction"),
                "mlConfidence": s.get("ml_confidence_score"),
            })

        return {
            "total_scans": total_scans,
            "threats_detected": threats_detected,
            "suspicious_files": suspicious_files,
            "clean_files": clean_files,
            "inconclusive_files": inconclusive_files,
            "recent_scans": recent_scans,
            "threat_distribution": {
                "malicious": threats_detected,
                "suspicious": suspicious_files,
                "clean": clean_files,
                "inconclusive": inconclusive_files
            }
        }

# Global singleton
scan_repository = ScanRepository()

