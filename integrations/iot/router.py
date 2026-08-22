"""RushX API routes for the IoT (Flexi Twin) integration.

All endpoints require an authenticated RushX user (existing JWT auth).
The frontend NEVER talks to Flexi Twin directly.
"""
from __future__ import annotations
import time
import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query

from .client import flexitwin_client, normalize_device

log = logging.getLogger("iot.router")

# Small in-process cache (list) to reduce upstream calls (rate limit is 10/min).
_LIST_CACHE_TTL_S = 25.0
_list_cache = {"at": 0.0, "data": None}


def make_iot_router(get_current_user, db):
    """Factory: returns an APIRouter wired to the given auth dependency + Motor db."""

    router = APIRouter(prefix="/iot", tags=["iot"])

    async def _fetch_devices(page_number: int, page_size: int, device_ids: Optional[List[str]]):
        # cache only the "unfiltered first page" list; skip cache for filtered/paginated calls
        cacheable = (page_number == 1 and page_size == 50 and not device_ids)
        if cacheable and _list_cache["data"] is not None and (time.monotonic() - _list_cache["at"]) < _LIST_CACHE_TTL_S:
            return _list_cache["data"]
        raw = await flexitwin_client.list_devices(page_number, page_size, device_ids)
        payload = {
            "provider": "flexitwin",
            "total_records": raw.get("totalRecords", 0),
            "page_number": page_number,
            "page_size": page_size,
            "message": raw.get("message", "OK"),
            "devices": [normalize_device(d) for d in raw.get("data", [])],
        }
        if cacheable:
            _list_cache["at"] = time.monotonic()
            _list_cache["data"] = payload
        return payload

    @router.get("/status")
    async def iot_status(user=Depends(get_current_user)):
        """Report integration configuration & documented capabilities."""
        return {
            "provider": "flexitwin",
            "configured": flexitwin_client.is_configured,
            "base_url": flexitwin_client.base_url,
            "supported_endpoints": ["GET /external/devices"],
            "not_supported": ["device_detail_endpoint", "telemetry_history", "soh", "temperature", "power_reported", "alarms", "websocket", "mqtt"],
            "rate_limit": "10 requests / minute / integration",
        }

    @router.get("/devices")
    async def list_devices(
        page_number: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=50),
        device_ids: Optional[str] = Query(None, description="Comma-separated positive integer device IDs"),
        user=Depends(get_current_user),
    ):
        ids = [x.strip() for x in device_ids.split(",")] if device_ids else None
        return await _fetch_devices(page_number, page_size, ids)

    @router.get("/devices/{device_id}")
    async def get_device(device_id: str, user=Depends(get_current_user)):
        """Fetch a single device.

        NOTE: Flexi Twin does not document a dedicated device-detail endpoint.
        We use the documented ``deviceIds`` filter on the list endpoint as the
        officially supported way to look up one device.
        """
        if not device_id.isdigit() or int(device_id) <= 0:
            raise HTTPException(status_code=400, detail={"success": False, "error": "Device id must be a positive integer"})
        payload = await flexitwin_client.list_devices(1, 1, [device_id])
        items = payload.get("data") or []
        if not items:
            raise HTTPException(status_code=404, detail={"success": False, "error": "Device not found"})
        return {"provider": "flexitwin", "device": normalize_device(items[0])}

    @router.get("/kpis")
    async def iot_kpis(user=Depends(get_current_user)):
        """Aggregate KPIs over the first page (up to 50 devices, per API cap)."""
        try:
            payload = await _fetch_devices(1, 50, None)
        except HTTPException as e:
            # Graceful degradation — expose zeros + reason (never leak credentials)
            reason = e.detail.get("error") if isinstance(e.detail, dict) else str(e.detail)
            return {"available": False, "reason": reason, "total": 0, "online": 0, "offline": 0, "charging": 0, "discharging": 0}
        devices = payload["devices"]
        online = sum(1 for d in devices if d["status"] == "online")
        offline = sum(1 for d in devices if d["status"] == "offline")
        charging = sum(1 for d in devices if d["charging"] is True)
        discharging = sum(1 for d in devices if d["charging"] is False)
        return {
            "available": True,
            "total": payload["total_records"],
            "on_page": len(devices),
            "online": online,
            "offline": offline,
            "charging": charging,
            "discharging": discharging,
        }

    @router.post("/assets/{asset_id}/link")
    async def link_asset_to_device(asset_id: str, manufacturer_device_id: str, user=Depends(get_current_user)):
        """Attach a Flexi Twin ``deviceId`` to an existing RushX Asset."""
        if not manufacturer_device_id.isdigit() or int(manufacturer_device_id) <= 0:
            raise HTTPException(400, detail={"success": False, "error": "manufacturer_device_id must be a positive integer"})
        result = await db.assets.update_one(
            {"id": asset_id},
            {"$set": {"manufacturer_device_id": str(manufacturer_device_id), "iot_provider": "flexitwin"}},
        )
        if result.matched_count == 0:
            raise HTTPException(404, detail={"success": False, "error": "Asset not found"})
        return {"success": True, "asset_id": asset_id, "manufacturer_device_id": manufacturer_device_id}

    return router
