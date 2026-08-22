"""Flexi Twin External API client.
Based on Flexi-Twin-External-API-Integration-Guide.
Only endpoints that are documented are implemented.

DOCUMENTED (as of v1.0 of the guide):
    GET /external/devices  — list devices (paginated, filter by deviceIds).

NOT DOCUMENTED (therefore NOT IMPLEMENTED here):
    - single-device detail
    - historical telemetry
    - SoH, power, temperature, charging status, alarms
    - websocket / MQTT streaming
"""
from __future__ import annotations
import os
import logging
import time
import asyncio
from typing import Optional, List, Dict, Any

import httpx
from fastapi import HTTPException

log = logging.getLogger("iot.flexitwin")


class FlexiTwinError(HTTPException):
    """Wraps IoT provider errors into safe FastAPI responses (no credential leakage)."""


class FlexiTwinClient:
    """Thin async wrapper for the Flexi Twin External API."""

    def __init__(self) -> None:
        self.base_url = os.environ.get("IOT_API_BASE_URL", "https://www.flexitwin.com/backend/api")
        self.integration_id = os.environ.get("IOT_INTEGRATION_ID", "")
        self.api_key = os.environ.get("IOT_API_KEY", "")
        # simple in-process rate-limit throttle: max 8/min (documented cap is 10/min)
        self._min_interval_s = 7.5
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    # ---------- Public API ----------
    @property
    def is_configured(self) -> bool:
        return bool(self.integration_id and self.api_key)

    async def list_devices(self, page_number: int = 1, page_size: int = 50,
                           device_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "pageNumber": max(1, int(page_number)),
            "pageSize": min(50, max(1, int(page_size))),  # documented cap = 50
        }
        if device_ids:
            # documented format: comma-separated positive integers
            valid = [str(int(d)) for d in device_ids if str(d).lstrip("-").isdigit() and int(d) > 0]
            if valid:
                params["deviceIds"] = ",".join(valid)
        return await self._get("/external/devices", params=params)

    # ---------- Internals ----------
    async def _throttle(self) -> None:
        async with self._lock:
            elapsed = time.monotonic() - self._last_call
            if elapsed < self._min_interval_s:
                await asyncio.sleep(self._min_interval_s - elapsed)
            self._last_call = time.monotonic()

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.is_configured:
            raise FlexiTwinError(status_code=503, detail={
                "success": False,
                "error": "IoT provider not configured on server",
                "hint": "Add IOT_INTEGRATION_ID and IOT_API_KEY environment variables.",
            })

        await self._throttle()

        url = f"{self.base_url.rstrip('/')}{path}"
        headers = {
            # exact header names per the Flexi Twin guide
            "X-Flexi-Integration-Id": self.integration_id,
            "X-Flexi-Api-Key": self.api_key,
            "Accept": "application/json",
        }

        log.info("IoT request started path=%s params=%s", path, {k: v for k, v in (params or {}).items() if k != "deviceIds"} | ({"deviceIds": "***" if params and "deviceIds" in params else None} if False else {}))

        try:
            async with httpx.AsyncClient(timeout=15.0) as http:
                r = await http.get(url, headers=headers, params=params)
        except httpx.TimeoutException:
            log.warning("IoT provider timeout path=%s", path)
            raise FlexiTwinError(status_code=504, detail={"success": False, "error": "IoT provider timeout"})
        except httpx.HTTPError as e:
            log.warning("IoT provider network failure path=%s err=%s", path, e.__class__.__name__)
            raise FlexiTwinError(status_code=502, detail={"success": False, "error": "IoT provider unavailable"})

        # Documented status codes: 200 / 400 / 401 / 429
        if r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                log.error("IoT provider returned malformed JSON")
                raise FlexiTwinError(status_code=502, detail={"success": False, "error": "Malformed IoT response"})
            log.info("IoT provider response received records=%s", data.get("totalRecords"))
            return data

        if r.status_code == 401:
            log.warning("IoT provider returned 401 (auth) path=%s", path)
            raise FlexiTwinError(status_code=502, detail={"success": False, "error": "IoT provider auth failed. Verify credentials on server."})
        if r.status_code == 403:
            raise FlexiTwinError(status_code=502, detail={"success": False, "error": "IoT provider forbidden"})
        if r.status_code == 400:
            raise FlexiTwinError(status_code=400, detail={"success": False, "error": "Invalid device id format (must be positive integers)"})
        if r.status_code == 404:
            raise FlexiTwinError(status_code=404, detail={"success": False, "error": "Device not found"})
        if r.status_code == 429:
            retry = r.headers.get("Retry-After", "60")
            raise FlexiTwinError(status_code=429, detail={"success": False, "error": "IoT provider rate limit exceeded", "retry_after_seconds": retry})
        if 500 <= r.status_code < 600:
            log.warning("IoT provider 5xx path=%s status=%s", path, r.status_code)
            raise FlexiTwinError(status_code=502, detail={"success": False, "error": "IoT provider unavailable"})

        # Fallback
        raise FlexiTwinError(status_code=502, detail={"success": False, "error": "IoT provider unexpected response"})


# module-level singleton (safe: httpx.AsyncClient is created per-call)
flexitwin_client = FlexiTwinClient()


# ---------- Normalization ----------
def normalize_device(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map Flexi Twin device snapshot to RushX canonical shape.

    Fields the Flexi Twin API does NOT provide are returned as null with an
    ``unsupported`` list so the frontend can show honest "N/A" instead of
    fabricated values.
    """
    device_status = raw.get("deviceStatus")
    voltage = raw.get("voltage")
    current = raw.get("current")
    # Power (W) is derivable from V and I. Documented as supported inputs.
    power = round(float(voltage) * float(current), 2) if (voltage is not None and current is not None) else None
    charging = None
    if current is not None:
        # Convention: negative current in the sample response indicates discharge.
        charging = float(current) > 0
    return {
        "device_id": str(raw.get("deviceId")) if raw.get("deviceId") is not None else None,
        "unique_id": raw.get("uniqueId"),
        "name": raw.get("deviceName"),
        "status": "online" if device_status == 1 else ("offline" if device_status == 2 else None),
        "device_status_code": device_status,
        "soc": raw.get("stateOfCharge"),
        "voltage": voltage,
        "current": current,
        "power": power,
        "charging": charging,
        "latitude": raw.get("latitude"),
        "longitude": raw.get("longitude"),
        "last_updated": raw.get("lastPingTime"),
        # Not supported by Flexi Twin documentation:
        "soh": None,
        "temperature": None,
        "faults": None,
        "unsupported_fields": ["soh", "temperature", "faults", "power_reported", "history", "alarms"],
    }
