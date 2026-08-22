"""RushGro PBaaS - Main FastAPI Server (multi-tenant enterprise SaaS)."""
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, APIRouter, Request, Response, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

from auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_token, gen_reset_token,
)
import models as M

# ---------- DB ----------
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI(title="RushGro PBaaS API", version="1.0.0")
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("rushgro")


# ---------- Helpers ----------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


def strip_id(doc: dict) -> dict:
    if doc and "_id" in doc:
        doc.pop("_id", None)
    return doc


async def audit(user: Optional[dict], action: str, entity: str, entity_id: str = None, details: str = ""):
    await db.audit_logs.insert_one({
        "id": new_id(),
        "user_id": user.get("id") if user else None,
        "user_email": user.get("email") if user else None,
        "action": action,
        "entity": entity,
        "entity_id": entity_id,
        "details": details,
        "created_at": now_iso(),
    })


async def notify(title: str, message: str, role: str = None, user_id: str = None, brand_id: str = None, type_: str = "info"):
    await db.notifications.insert_one({
        "id": new_id(),
        "user_id": user_id,
        "role": role,
        "brand_id": brand_id,
        "title": title,
        "message": message,
        "type": type_,
        "read": False,
        "created_at": now_iso(),
    })
    log.info(f"[NOTIFY] {title} - {message}")


# ---------- Auth Dependencies ----------
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            token = header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user.pop("_id", None)
        user.pop("password_hash", None)
        return user
    except jwt_expired_error():
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def jwt_expired_error():
    import jwt
    return jwt.ExpiredSignatureError


def require_role(*roles: str):
    async def _dep(user: dict = Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {', '.join(roles)}")
        return user
    return _dep


def set_auth_cookies(response: Response, access: str, refresh: str):
    response.set_cookie("access_token", access, httponly=True, secure=False, samesite="lax", max_age=8 * 3600, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=False, samesite="lax", max_age=7 * 86400, path="/")


# ---------- AUTH ROUTES ----------
from pydantic import BaseModel, EmailStr


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class SignupIn(BaseModel):
    name: str
    email: EmailStr
    password: str
    company: str
    phone: Optional[str] = ""
    city: Optional[str] = ""


class ForgotIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str
    new_password: str


@api.post("/auth/signup")
async def signup(payload: SignupIn, response: Response):
    """Public self-serve signup — creates a Brand + Brand Admin user + auto-login."""
    email = payload.email.lower().strip()
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if await db.users.find_one({"email": email}):
        raise HTTPException(409, "An account with this email already exists")

    brand_id = new_id()
    now = now_iso()
    await db.brands.insert_one({
        "id": brand_id, "name": payload.company.strip(), "logo_url": None,
        "gst_number": None, "pan": None,
        "email": email, "phone": payload.phone or "",
        "address": "", "city": payload.city or "", "state": "", "pincode": "",
        "primary_contact": payload.name, "subscription_plan_id": None,
        "status": "pending", "created_at": now,
    })

    user_id = new_id()
    user_doc = {
        "id": user_id, "email": email, "password_hash": hash_password(payload.password),
        "name": payload.name.strip(), "phone": payload.phone or "",
        "role": "brand_admin", "brand_id": brand_id,
        "status": "active", "created_at": now,
    }
    await db.users.insert_one(user_doc)

    access = create_access_token(user_id, email, "brand_admin")
    refresh = create_refresh_token(user_id)
    set_auth_cookies(response, access, refresh)

    await notify("New brand signup", f"{payload.company} ({email}) just signed up.",
                 role="super_admin", type_="success")
    user_doc.pop("password_hash", None)
    user_doc.pop("_id", None)
    await audit(user_doc, "signup", "user", user_id, f"Self-serve signup for brand {payload.company}")
    return {"user": user_doc, "access_token": access}


@api.post("/auth/login")
async def login(payload: LoginIn, response: Response, request: Request):
    email = payload.email.lower().strip()
    ip = request.client.host if request.client else "unknown"
    key = f"{ip}:{email}"

    # brute-force lockout (>=5 failed attempts within 15 min window)
    attempts = await db.login_attempts.find_one({"key": key})
    if attempts and attempts.get("count", 0) >= 5:
        locked_until = attempts.get("locked_until")
        if locked_until and datetime.fromisoformat(locked_until) > datetime.now(timezone.utc):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user["password_hash"]):
        from pymongo import ReturnDocument
        updated = await db.login_attempts.find_one_and_update(
            {"key": key},
            {"$inc": {"count": 1},
             "$set": {"locked_until": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        if updated and updated.get("count", 0) >= 5:
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user.get("status") != "active":
        raise HTTPException(status_code=403, detail="Account is inactive")

    await db.login_attempts.delete_one({"key": key})

    access = create_access_token(user["id"], user["email"], user["role"])
    refresh = create_refresh_token(user["id"])
    set_auth_cookies(response, access, refresh)

    user.pop("_id", None)
    user.pop("password_hash", None)
    await audit(user, "login", "user", user["id"], "User logged in")
    return {"user": user, "access_token": access}


@api.post("/auth/logout")
async def logout(response: Response, user: dict = Depends(get_current_user)):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    await audit(user, "logout", "user", user["id"], "User logged out")
    return {"ok": True}


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


@api.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = decode_token(token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        access = create_access_token(user["id"], user["email"], user["role"])
        response.set_cookie("access_token", access, httponly=True, secure=False, samesite="lax", max_age=8 * 3600, path="/")
        return {"ok": True}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@api.post("/auth/forgot-password")
async def forgot_password(payload: ForgotIn):
    user = await db.users.find_one({"email": payload.email.lower().strip()})
    if user:
        token = gen_reset_token()
        await db.password_reset_tokens.insert_one({
            "token": token,
            "user_id": user["id"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "used": False,
        })
        log.info(f"[PASSWORD RESET] link: /reset-password?token={token} for {user['email']}")
    return {"ok": True, "message": "If the email exists, a reset link has been sent"}


@api.post("/auth/reset-password")
async def reset_password(payload: ResetIn):
    rec = await db.password_reset_tokens.find_one({"token": payload.token, "used": False})
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid or used token")
    if datetime.fromisoformat(rec["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token expired")
    await db.users.update_one({"id": rec["user_id"]}, {"$set": {"password_hash": hash_password(payload.new_password)}})
    await db.password_reset_tokens.update_one({"token": payload.token}, {"$set": {"used": True}})
    return {"ok": True}


# ---------- Generic CRUD helpers ----------
async def list_docs(collection, filters: dict, skip: int, limit: int, sort_by: str = "created_at", sort_dir: int = -1):
    cursor = db[collection].find(filters, {"_id": 0}).sort(sort_by, sort_dir).skip(skip).limit(limit)
    items = await cursor.to_list(length=limit)
    total = await db[collection].count_documents(filters)
    return {"items": items, "total": total}


def build_search(fields: List[str], q: Optional[str]) -> dict:
    if not q:
        return {}
    import re
    rx = {"$regex": re.escape(q), "$options": "i"}
    return {"$or": [{f: rx} for f in fields]}


# ---------- BRANDS ----------
@api.post("/brands", response_model=M.BrandOut)
async def create_brand(data: M.BrandCreate, user: dict = Depends(require_role("super_admin"))):
    doc = data.model_dump()
    doc["id"] = new_id()
    doc["created_at"] = now_iso()
    await db.brands.insert_one(doc)
    await audit(user, "create", "brand", doc["id"], f"Created brand {doc['name']}")
    return strip_id(doc)


@api.get("/brands")
async def list_brands(
    q: Optional[str] = None, city: Optional[str] = None, status: Optional[str] = None,
    skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user),
):
    filters = build_search(["name", "email", "gst_number", "phone"], q)
    if city:
        filters["city"] = city
    if status:
        filters["status"] = status
    if user["role"] == "brand_admin":
        filters["id"] = user.get("brand_id")
    return await list_docs("brands", filters, skip, limit)


@api.get("/brands/{brand_id}")
async def get_brand(brand_id: str, user: dict = Depends(get_current_user)):
    if user["role"] == "brand_admin" and user.get("brand_id") != brand_id:
        raise HTTPException(403, "Forbidden")
    brand = await db.brands.find_one({"id": brand_id}, {"_id": 0})
    if not brand:
        raise HTTPException(404, "Brand not found")
    return brand


@api.patch("/brands/{brand_id}")
async def update_brand(brand_id: str, data: M.BrandUpdate, user: dict = Depends(require_role("super_admin", "brand_admin"))):
    if user["role"] == "brand_admin" and user.get("brand_id") != brand_id:
        raise HTTPException(403, "Forbidden")
    upd = {k: v for k, v in data.model_dump().items() if v is not None}
    if not upd:
        raise HTTPException(400, "No changes")
    await db.brands.update_one({"id": brand_id}, {"$set": upd})
    await audit(user, "update", "brand", brand_id, str(upd))
    return await db.brands.find_one({"id": brand_id}, {"_id": 0})


@api.delete("/brands/{brand_id}")
async def delete_brand(brand_id: str, user: dict = Depends(require_role("super_admin"))):
    await db.brands.delete_one({"id": brand_id})
    await audit(user, "delete", "brand", brand_id)
    return {"ok": True}


# ---------- OUTLETS ----------
@api.post("/outlets", response_model=M.OutletOut)
async def create_outlet(data: M.OutletCreate, user: dict = Depends(require_role("super_admin", "brand_admin"))):
    if user["role"] == "brand_admin" and user.get("brand_id") != data.brand_id:
        raise HTTPException(403, "Forbidden")
    doc = data.model_dump()
    doc["id"] = new_id()
    doc["code"] = doc.get("code") or f"OUT-{doc['id'][:6].upper()}"
    doc["created_at"] = now_iso()
    await db.outlets.insert_one(doc)
    await audit(user, "create", "outlet", doc["id"], f"Created outlet {doc['name']}")
    return strip_id(doc)


@api.get("/outlets")
async def list_outlets(
    q: Optional[str] = None, brand_id: Optional[str] = None, city: Optional[str] = None,
    status: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user),
):
    filters = build_search(["name", "code", "address", "city"], q)
    if brand_id:
        filters["brand_id"] = brand_id
    if city:
        filters["city"] = city
    if status:
        filters["status"] = status
    if user["role"] == "brand_admin":
        filters["brand_id"] = user.get("brand_id")
    elif user["role"] == "outlet_user":
        filters["id"] = user.get("outlet_id")
    return await list_docs("outlets", filters, skip, limit)


@api.get("/outlets/{outlet_id}")
async def get_outlet(outlet_id: str, user: dict = Depends(get_current_user)):
    out = await db.outlets.find_one({"id": outlet_id}, {"_id": 0})
    if not out:
        raise HTTPException(404, "Outlet not found")
    return out


@api.patch("/outlets/{outlet_id}")
async def update_outlet(outlet_id: str, data: M.OutletUpdate, user: dict = Depends(require_role("super_admin", "brand_admin"))):
    upd = {k: v for k, v in data.model_dump().items() if v is not None}
    if not upd:
        raise HTTPException(400, "No changes")
    await db.outlets.update_one({"id": outlet_id}, {"$set": upd})
    await audit(user, "update", "outlet", outlet_id, str(upd))
    return await db.outlets.find_one({"id": outlet_id}, {"_id": 0})


@api.delete("/outlets/{outlet_id}")
async def delete_outlet(outlet_id: str, user: dict = Depends(require_role("super_admin"))):
    await db.outlets.delete_one({"id": outlet_id})
    await audit(user, "delete", "outlet", outlet_id)
    return {"ok": True}


# ---------- MANUFACTURERS ----------
@api.post("/manufacturers", response_model=M.ManufacturerOut)
async def create_manufacturer(data: M.ManufacturerCreate, user: dict = Depends(require_role("super_admin"))):
    doc = data.model_dump()
    doc["id"] = new_id()
    doc["created_at"] = now_iso()
    await db.manufacturers.insert_one(doc)
    await audit(user, "create", "manufacturer", doc["id"], f"Created manufacturer {doc['name']}")
    return strip_id(doc)


@api.get("/manufacturers")
async def list_manufacturers(q: Optional[str] = None, city: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user)):
    filters = build_search(["name", "email", "phone", "city"], q)
    if city:
        filters["city"] = city
    if user["role"] == "manufacturer_user":
        filters["id"] = user.get("manufacturer_id")
    return await list_docs("manufacturers", filters, skip, limit)


@api.patch("/manufacturers/{mid}")
async def update_manufacturer(mid: str, data: M.ManufacturerUpdate, user: dict = Depends(require_role("super_admin", "manufacturer_user"))):
    if user["role"] == "manufacturer_user" and user.get("manufacturer_id") != mid:
        raise HTTPException(403, "Forbidden")
    upd = {k: v for k, v in data.model_dump().items() if v is not None}
    await db.manufacturers.update_one({"id": mid}, {"$set": upd})
    await audit(user, "update", "manufacturer", mid, str(upd))
    return await db.manufacturers.find_one({"id": mid}, {"_id": 0})


@api.delete("/manufacturers/{mid}")
async def delete_manufacturer(mid: str, user: dict = Depends(require_role("super_admin"))):
    await db.manufacturers.delete_one({"id": mid})
    await audit(user, "delete", "manufacturer", mid)
    return {"ok": True}


# ---------- ASSETS ----------
@api.post("/assets", response_model=M.AssetOut)
async def create_asset(data: M.AssetCreate, user: dict = Depends(require_role("super_admin", "manufacturer_user"))):
    doc = data.model_dump()
    doc["id"] = new_id()
    doc["created_at"] = now_iso()
    await db.assets.insert_one(doc)
    # bump manufacturer inventory
    await db.manufacturers.update_one({"id": data.manufacturer_id}, {"$inc": {"inventory_available": 1}})
    await audit(user, "create", "asset", doc["id"], f"Created asset {doc['serial_number']}")
    return strip_id(doc)


@api.get("/assets")
async def list_assets(
    q: Optional[str] = None, brand_id: Optional[str] = None, outlet_id: Optional[str] = None,
    manufacturer_id: Optional[str] = None, status: Optional[str] = None,
    skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user),
):
    filters = build_search(["serial_number", "model", "remarks"], q)
    if brand_id: filters["brand_id"] = brand_id
    if outlet_id: filters["outlet_id"] = outlet_id
    if manufacturer_id: filters["manufacturer_id"] = manufacturer_id
    if status: filters["status"] = status
    if user["role"] == "brand_admin":
        filters["brand_id"] = user.get("brand_id")
    elif user["role"] == "outlet_user":
        filters["outlet_id"] = user.get("outlet_id")
    elif user["role"] == "manufacturer_user":
        filters["manufacturer_id"] = user.get("manufacturer_id")
    return await list_docs("assets", filters, skip, limit)


@api.patch("/assets/{aid}")
async def update_asset(aid: str, data: M.AssetUpdate, user: dict = Depends(require_role("super_admin", "manufacturer_user", "rushserv_user"))):
    upd = {k: v for k, v in data.model_dump().items() if v is not None}
    await db.assets.update_one({"id": aid}, {"$set": upd})
    await audit(user, "update", "asset", aid, str(upd))
    return await db.assets.find_one({"id": aid}, {"_id": 0})


@api.delete("/assets/{aid}")
async def delete_asset(aid: str, user: dict = Depends(require_role("super_admin"))):
    await db.assets.delete_one({"id": aid})
    await audit(user, "delete", "asset", aid)
    return {"ok": True}


@api.post("/assets/{aid}/assign")
async def assign_asset(aid: str, outlet_id: str, user: dict = Depends(require_role("super_admin"))):
    outlet = await db.outlets.find_one({"id": outlet_id})
    if not outlet:
        raise HTTPException(404, "Outlet not found")
    now = now_iso()
    await db.assets.update_one({"id": aid}, {"$set": {
        "outlet_id": outlet_id, "brand_id": outlet["brand_id"],
        "status": "installed", "installation_date": now,
    }})
    await db.outlets.update_one({"id": outlet_id}, {"$set": {"installation_status": "installed"}})
    # auto-create subscription
    asset = await db.assets.find_one({"id": aid})
    plan = await db.subscription_plans.find_one({"capacity_kw": asset["capacity_kw"], "status": "active"})
    if plan:
        sub_id = new_id()
        await db.subscriptions.insert_one({
            "id": sub_id, "brand_id": outlet["brand_id"], "outlet_id": outlet_id, "asset_id": aid,
            "plan_id": plan["id"], "start_date": now,
            "next_billing_date": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "status": "active", "created_at": now,
        })
        # first invoice
        inv_no = f"INV-{datetime.now(timezone.utc).strftime('%Y%m')}-{new_id()[:6].upper()}"
        subtotal = plan["monthly_price"]
        gst = round(subtotal * plan["gst_percent"] / 100, 2)
        await db.invoices.insert_one({
            "id": new_id(), "invoice_number": inv_no, "brand_id": outlet["brand_id"], "outlet_id": outlet_id,
            "subscription_id": sub_id, "plan_name": plan["name"], "subtotal": subtotal, "gst_amount": gst,
            "total": subtotal + gst, "status": "pending",
            "due_date": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            "created_at": now,
        })
        await notify("Installation complete", f"Asset {asset['serial_number']} installed at outlet.", role="brand_admin", brand_id=outlet["brand_id"], type_="success")
    await audit(user, "assign", "asset", aid, f"Assigned to outlet {outlet_id}")
    return {"ok": True}


# ---------- SUBSCRIPTION PLANS ----------
@api.post("/plans", response_model=M.SubscriptionPlanOut)
async def create_plan(data: M.SubscriptionPlanCreate, user: dict = Depends(require_role("super_admin"))):
    doc = data.model_dump()
    doc["id"] = new_id()
    doc["created_at"] = now_iso()
    await db.subscription_plans.insert_one(doc)
    await audit(user, "create", "plan", doc["id"], doc["name"])
    return strip_id(doc)


@api.get("/plans")
async def list_plans(user: dict = Depends(get_current_user)):
    items = await db.subscription_plans.find({}, {"_id": 0}).sort("monthly_price", 1).to_list(100)
    return {"items": items, "total": len(items)}


@api.patch("/plans/{pid}")
async def update_plan(pid: str, data: dict, user: dict = Depends(require_role("super_admin"))):
    await db.subscription_plans.update_one({"id": pid}, {"$set": data})
    await audit(user, "update", "plan", pid, str(data))
    return await db.subscription_plans.find_one({"id": pid}, {"_id": 0})


@api.delete("/plans/{pid}")
async def delete_plan(pid: str, user: dict = Depends(require_role("super_admin"))):
    await db.subscription_plans.delete_one({"id": pid})
    await audit(user, "delete", "plan", pid)
    return {"ok": True}


# ---------- SUBSCRIPTIONS ----------
@api.get("/subscriptions")
async def list_subscriptions(brand_id: Optional[str] = None, status: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user)):
    filters = {}
    if brand_id: filters["brand_id"] = brand_id
    if status: filters["status"] = status
    if user["role"] == "brand_admin":
        filters["brand_id"] = user.get("brand_id")
    elif user["role"] == "outlet_user":
        filters["outlet_id"] = user.get("outlet_id")
    return await list_docs("subscriptions", filters, skip, limit)


@api.patch("/subscriptions/{sid}/status")
async def set_sub_status(sid: str, status: str, user: dict = Depends(require_role("super_admin"))):
    await db.subscriptions.update_one({"id": sid}, {"$set": {"status": status}})
    await audit(user, "update", "subscription", sid, f"status={status}")
    return {"ok": True}


# ---------- INVOICES ----------
@api.get("/invoices")
async def list_invoices(brand_id: Optional[str] = None, status: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user)):
    filters = {}
    if brand_id: filters["brand_id"] = brand_id
    if status: filters["status"] = status
    if user["role"] == "brand_admin":
        filters["brand_id"] = user.get("brand_id")
    elif user["role"] == "outlet_user":
        filters["outlet_id"] = user.get("outlet_id")
    return await list_docs("invoices", filters, skip, limit)


@api.post("/invoices/{iid}/pay")
async def pay_invoice(iid: str, user: dict = Depends(require_role("super_admin", "brand_admin"))):
    """Mark invoice as paid. In production, integrate PhonePe webhook here."""
    inv = await db.invoices.find_one({"id": iid})
    if not inv:
        raise HTTPException(404, "Invoice not found")
    await db.invoices.update_one({"id": iid}, {"$set": {"status": "paid", "paid_at": now_iso()}})
    await db.payments.insert_one({
        "id": new_id(), "invoice_id": iid, "amount": inv["total"], "method": "phonepe",
        "reference": f"PP-{new_id()[:8].upper()}", "status": "success", "created_at": now_iso(),
    })
    await audit(user, "payment", "invoice", iid, f"Paid ₹{inv['total']}")
    return {"ok": True}


# ---------- MAINTENANCE ----------
@api.post("/maintenance", response_model=M.MaintenanceOut)
async def create_ticket(data: M.MaintenanceCreate, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["id"] = new_id()
    doc["ticket_id"] = f"TKT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{doc['id'][:5].upper()}"
    doc["created_at"] = now_iso()
    await db.maintenance_tickets.insert_one(doc)
    await notify("New maintenance ticket", f"{doc['ticket_id']}: {doc['issue']}", role="rushserv_user", type_="warning")
    await audit(user, "create", "maintenance", doc["id"], doc["ticket_id"])
    return strip_id(doc)


@api.get("/maintenance")
async def list_tickets(brand_id: Optional[str] = None, status: Optional[str] = None, priority: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user)):
    filters = {}
    if brand_id: filters["brand_id"] = brand_id
    if status: filters["status"] = status
    if priority: filters["priority"] = priority
    if user["role"] == "brand_admin":
        filters["brand_id"] = user.get("brand_id")
    elif user["role"] == "outlet_user":
        filters["outlet_id"] = user.get("outlet_id")
    elif user["role"] == "rushserv_user":
        filters["assigned_engineer"] = user["id"]
    return await list_docs("maintenance_tickets", filters, skip, limit)


@api.patch("/maintenance/{tid}")
async def update_ticket(tid: str, data: M.MaintenanceUpdate, user: dict = Depends(get_current_user)):
    upd = {k: v for k, v in data.model_dump().items() if v is not None}
    await db.maintenance_tickets.update_one({"id": tid}, {"$set": upd})
    await audit(user, "update", "maintenance", tid, str(upd))
    return await db.maintenance_tickets.find_one({"id": tid}, {"_id": 0})


# ---------- WARRANTY ----------
@api.post("/warranty", response_model=M.WarrantyOut)
async def create_claim(data: M.WarrantyCreate, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["id"] = new_id()
    doc["claim_id"] = f"WCM-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{doc['id'][:5].upper()}"
    doc["created_at"] = now_iso()
    await db.warranty_claims.insert_one(doc)
    await notify("New warranty claim", doc["claim_id"], role="super_admin", type_="info")
    await audit(user, "create", "warranty", doc["id"], doc["claim_id"])
    return strip_id(doc)


@api.get("/warranty")
async def list_claims(brand_id: Optional[str] = None, status: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user)):
    filters = {}
    if brand_id: filters["brand_id"] = brand_id
    if status: filters["approval_status"] = status
    if user["role"] == "brand_admin":
        filters["brand_id"] = user.get("brand_id")
    elif user["role"] == "outlet_user":
        filters["outlet_id"] = user.get("outlet_id")
    elif user["role"] == "manufacturer_user":
        filters["manufacturer_id"] = user.get("manufacturer_id")
    return await list_docs("warranty_claims", filters, skip, limit)


@api.patch("/warranty/{cid}")
async def update_claim(cid: str, data: M.WarrantyUpdate, user: dict = Depends(get_current_user)):
    upd = {k: v for k, v in data.model_dump().items() if v is not None}
    await db.warranty_claims.update_one({"id": cid}, {"$set": upd})
    await audit(user, "update", "warranty", cid, str(upd))
    return await db.warranty_claims.find_one({"id": cid}, {"_id": 0})


# ---------- USERS ----------
@api.post("/users", response_model=M.UserOut)
async def create_user(data: M.UserCreate, user: dict = Depends(require_role("super_admin"))):
    existing = await db.users.find_one({"email": data.email.lower()})
    if existing:
        raise HTTPException(409, "Email already exists")
    doc = data.model_dump()
    doc["email"] = doc["email"].lower()
    doc["password_hash"] = hash_password(doc.pop("password"))
    doc["id"] = new_id()
    doc["created_at"] = now_iso()
    await db.users.insert_one(doc)
    await audit(user, "create", "user", doc["id"], doc["email"])
    doc.pop("password_hash", None)
    return strip_id(doc)


@api.get("/users")
async def list_users(q: Optional[str] = None, role: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(require_role("super_admin"))):
    filters = build_search(["name", "email", "phone"], q)
    if role: filters["role"] = role
    cursor = db.users.find(filters, {"_id": 0, "password_hash": 0}).sort("created_at", -1).skip(skip).limit(limit)
    items = await cursor.to_list(length=limit)
    total = await db.users.count_documents(filters)
    return {"items": items, "total": total}


@api.patch("/users/{uid}")
async def update_user(uid: str, data: M.UserUpdate, user: dict = Depends(require_role("super_admin"))):
    upd = {k: v for k, v in data.model_dump().items() if v is not None}
    await db.users.update_one({"id": uid}, {"$set": upd})
    await audit(user, "update", "user", uid, str(upd))
    doc = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0})
    return doc


@api.delete("/users/{uid}")
async def delete_user(uid: str, user: dict = Depends(require_role("super_admin"))):
    await db.users.delete_one({"id": uid})
    await audit(user, "delete", "user", uid)
    return {"ok": True}


@api.post("/users/{uid}/reset-password")
async def admin_reset(uid: str, new_password: str, user: dict = Depends(require_role("super_admin"))):
    await db.users.update_one({"id": uid}, {"$set": {"password_hash": hash_password(new_password)}})
    await audit(user, "reset_password", "user", uid)
    return {"ok": True}


# ---------- NOTIFICATIONS ----------
@api.get("/notifications")
async def list_notifications(unread_only: bool = False, skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user)):
    filters = {"$or": [{"user_id": user["id"]}, {"role": user["role"]}, {"brand_id": user.get("brand_id")}]}
    if unread_only:
        filters["read"] = False
    return await list_docs("notifications", filters, skip, limit)


@api.post("/notifications/{nid}/read")
async def mark_read(nid: str, user: dict = Depends(get_current_user)):
    await db.notifications.update_one({"id": nid}, {"$set": {"read": True}})
    return {"ok": True}


@api.post("/notifications/read-all")
async def read_all(user: dict = Depends(get_current_user)):
    await db.notifications.update_many({"$or": [{"user_id": user["id"]}, {"role": user["role"]}]}, {"$set": {"read": True}})
    return {"ok": True}


# ---------- AUDIT LOGS ----------
@api.get("/audit-logs")
async def list_audit(skip: int = 0, limit: int = 100, user: dict = Depends(require_role("super_admin"))):
    return await list_docs("audit_logs", {}, skip, limit)


# ---------- DASHBOARD ----------
@api.get("/dashboard/kpis")
async def dashboard_kpis(user: dict = Depends(get_current_user)):
    scope = {}
    if user["role"] == "brand_admin":
        scope = {"brand_id": user.get("brand_id")}
    total_brands = await db.brands.count_documents({}) if user["role"] == "super_admin" else 1
    total_outlets = await db.outlets.count_documents(scope)
    total_assets = await db.assets.count_documents(scope)
    installed_assets = await db.assets.count_documents({**scope, "status": "installed"})
    available_inv = await db.assets.count_documents({**scope, "status": "in_inventory"}) if user["role"] == "super_admin" else 0
    active_subs = await db.subscriptions.count_documents({**scope, "status": "active"})
    pending_installs = await db.outlets.count_documents({**scope, "installation_status": {"$in": ["not_installed", "scheduled"]}})
    pending_maint = await db.maintenance_tickets.count_documents({**scope, "status": {"$in": ["open", "assigned", "in_progress"]}})
    warranty_claims = await db.warranty_claims.count_documents({**scope, "approval_status": "pending"})
    total_mrr = 0.0
    async for sub in db.subscriptions.find({**scope, "status": "active"}):
        plan = await db.subscription_plans.find_one({"id": sub["plan_id"]})
        if plan:
            total_mrr += plan["monthly_price"]
    active_mfrs = await db.manufacturers.count_documents({"contract_status": "active"}) if user["role"] == "super_admin" else 0
    return {
        "total_brands": total_brands,
        "total_outlets": total_outlets,
        "total_assets": total_assets,
        "installed_assets": installed_assets,
        "available_inventory": available_inv,
        "active_subscriptions": active_subs,
        "pending_installations": pending_installs,
        "pending_maintenance": pending_maint,
        "warranty_claims": warranty_claims,
        "monthly_revenue": total_mrr,
        "annual_revenue": total_mrr * 12,
        "active_manufacturers": active_mfrs,
    }


@api.get("/dashboard/charts")
async def dashboard_charts(user: dict = Depends(get_current_user)):
    # revenue trend last 6 months (compute from invoices)
    now = datetime.now(timezone.utc)
    trend = []
    for i in range(5, -1, -1):
        m = (now.replace(day=1) - timedelta(days=i * 30)).strftime("%Y-%m")
        agg = await db.invoices.aggregate([
            {"$match": {"status": "paid", "paid_at": {"$regex": f"^{m}"}}},
            {"$group": {"_id": None, "total": {"$sum": "$total"}}},
        ]).to_list(1)
        trend.append({"month": m, "revenue": agg[0]["total"] if agg else 0})
    # assets by manufacturer
    by_mfr = []
    async for m in db.manufacturers.find({}):
        cnt = await db.assets.count_documents({"manufacturer_id": m["id"]})
        by_mfr.append({"name": m["name"], "count": cnt})
    # assets by city
    by_city_pipeline = [{"$group": {"_id": "$city", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}, {"$limit": 8}]
    by_city_docs = await db.outlets.aggregate(by_city_pipeline).to_list(20)
    by_city = [{"city": d["_id"] or "Unknown", "count": d["count"]} for d in by_city_docs]
    # subscription distribution
    sub_dist = []
    async for p in db.subscription_plans.find({}):
        cnt = await db.subscriptions.count_documents({"plan_id": p["id"], "status": "active"})
        sub_dist.append({"name": p["name"], "value": cnt})
    return {"revenue_trend": trend, "assets_by_manufacturer": by_mfr, "assets_by_city": by_city, "subscription_distribution": sub_dist}


@api.get("/dashboard/recent-activities")
async def recent_activities(user: dict = Depends(get_current_user)):
    logs = await db.audit_logs.find({}, {"_id": 0}).sort("created_at", -1).limit(15).to_list(15)
    return {"items": logs}


# =====================================================================
# PHASE 2 EXTENSIONS - Enterprise Asset Management OS
# All new endpoints, backward-compatible with existing modules.
# =====================================================================

# ---------- CAPITAL PARTNERS ----------
@api.post("/capital-partners")
async def cp_create(data: dict, user: dict = Depends(require_role("super_admin"))):
    doc = {**data, "id": new_id(), "created_at": now_iso()}
    doc.setdefault("status", "active")
    doc.setdefault("capital_deployed", 0)
    doc.setdefault("total_commitment", 0)
    doc["available_capital"] = float(doc["total_commitment"]) - float(doc.get("capital_deployed", 0))
    await db.capital_partners.insert_one(doc)
    await audit(user, "create", "capital_partner", doc["id"], doc.get("name", ""))
    return strip_id(doc)

@api.get("/capital-partners")
async def cp_list(q: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(require_role("super_admin"))):
    filters = build_search(["name", "contact_person", "email", "capital_type"], q)
    return await list_docs("capital_partners", filters, skip, limit)

@api.patch("/capital-partners/{cid}")
async def cp_update(cid: str, data: dict, user: dict = Depends(require_role("super_admin"))):
    if "total_commitment" in data or "capital_deployed" in data:
        cur = await db.capital_partners.find_one({"id": cid})
        tc = float(data.get("total_commitment", cur.get("total_commitment", 0)))
        cd = float(data.get("capital_deployed", cur.get("capital_deployed", 0)))
        data["available_capital"] = tc - cd
    await db.capital_partners.update_one({"id": cid}, {"$set": data})
    await audit(user, "update", "capital_partner", cid, str(data))
    return await db.capital_partners.find_one({"id": cid}, {"_id": 0})

@api.delete("/capital-partners/{cid}")
async def cp_delete(cid: str, user: dict = Depends(require_role("super_admin"))):
    await db.capital_partners.delete_one({"id": cid})
    await audit(user, "delete", "capital_partner", cid)
    return {"ok": True}


# ---------- ASSET POOLS ----------
@api.post("/asset-pools")
async def pool_create(data: dict, user: dict = Depends(require_role("super_admin"))):
    doc = {**data, "id": new_id(), "created_at": now_iso()}
    doc.setdefault("asset_ids", [])
    doc.setdefault("investor_ids", [])
    doc["number_of_assets"] = len(doc.get("asset_ids", []))
    await db.asset_pools.insert_one(doc)
    await audit(user, "create", "asset_pool", doc["id"], doc.get("name", ""))
    return strip_id(doc)

@api.get("/asset-pools")
async def pool_list(skip: int = 0, limit: int = 50, user: dict = Depends(require_role("super_admin"))):
    return await list_docs("asset_pools", {}, skip, limit)

@api.patch("/asset-pools/{pid}")
async def pool_update(pid: str, data: dict, user: dict = Depends(require_role("super_admin"))):
    if "asset_ids" in data:
        data["number_of_assets"] = len(data["asset_ids"])
    await db.asset_pools.update_one({"id": pid}, {"$set": data})
    await audit(user, "update", "asset_pool", pid)
    return await db.asset_pools.find_one({"id": pid}, {"_id": 0})

@api.delete("/asset-pools/{pid}")
async def pool_delete(pid: str, user: dict = Depends(require_role("super_admin"))):
    await db.asset_pools.delete_one({"id": pid})
    return {"ok": True}


# ---------- RECOVERY ----------
@api.post("/recovery")
async def rec_create(data: dict, user: dict = Depends(require_role("super_admin", "rushserv_user"))):
    doc = {**data, "id": new_id(), "created_at": now_iso()}
    doc["recovery_id"] = f"REC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{doc['id'][:5].upper()}"
    doc.setdefault("status", "open")
    await db.recovery_cases.insert_one(doc)
    if data.get("asset_id"):
        await db.assets.update_one({"id": data["asset_id"]}, {"$set": {"status": "retired"}})
    await audit(user, "create", "recovery", doc["id"], doc["recovery_id"])
    return strip_id(doc)

@api.get("/recovery")
async def rec_list(skip: int = 0, limit: int = 50, user: dict = Depends(require_role("super_admin", "rushserv_user"))):
    return await list_docs("recovery_cases", {}, skip, limit)

@api.patch("/recovery/{rid}")
async def rec_update(rid: str, data: dict, user: dict = Depends(require_role("super_admin", "rushserv_user"))):
    await db.recovery_cases.update_one({"id": rid}, {"$set": data})
    await audit(user, "update", "recovery", rid, str(data))
    return await db.recovery_cases.find_one({"id": rid}, {"_id": 0})

@api.delete("/recovery/{rid}")
async def rec_delete(rid: str, user: dict = Depends(require_role("super_admin"))):
    await db.recovery_cases.delete_one({"id": rid})
    return {"ok": True}


# ---------- APPROVALS ----------
@api.post("/approvals")
async def appr_create(data: dict, user: dict = Depends(get_current_user)):
    doc = {**data, "id": new_id(), "created_at": now_iso(),
           "requester_id": user["id"], "requester_email": user["email"],
           "status": "pending", "timeline": [{"stage": "requested", "at": now_iso(), "by": user["email"]}]}
    await db.approvals.insert_one(doc)
    await notify("New approval request", doc.get("title", "Approval needed"), role="super_admin", type_="warning")
    await audit(user, "create", "approval", doc["id"], doc.get("title", ""))
    return strip_id(doc)

@api.get("/approvals")
async def appr_list(status: Optional[str] = None, skip: int = 0, limit: int = 50, user: dict = Depends(get_current_user)):
    filters = {}
    if status: filters["status"] = status
    if user["role"] != "super_admin":
        filters["requester_id"] = user["id"]
    return await list_docs("approvals", filters, skip, limit)

@api.post("/approvals/{aid}/decision")
async def appr_decide(aid: str, decision: str, comments: str = "", user: dict = Depends(require_role("super_admin"))):
    if decision not in ("approved", "rejected"):
        raise HTTPException(400, "decision must be approved|rejected")
    entry = {"stage": decision, "at": now_iso(), "by": user["email"], "comments": comments}
    await db.approvals.update_one({"id": aid}, {"$set": {"status": decision, "decided_at": now_iso(), "approver_email": user["email"], "comments": comments}, "$push": {"timeline": entry}})
    await audit(user, decision, "approval", aid, comments)
    return await db.approvals.find_one({"id": aid}, {"_id": 0})


# ---------- DOCUMENT VAULT ----------
@api.post("/documents")
async def doc_create(data: dict, user: dict = Depends(get_current_user)):
    doc = {**data, "id": new_id(), "created_at": now_iso(),
           "uploader_email": user["email"], "version": 1}
    await db.documents.insert_one(doc)
    await audit(user, "upload", "document", doc["id"], doc.get("name", ""))
    return strip_id(doc)

@api.get("/documents")
async def doc_list(q: Optional[str] = None, type: Optional[str] = None, skip: int = 0, limit: int = 100, user: dict = Depends(get_current_user)):
    filters = build_search(["name", "description", "type", "related_entity"], q)
    if type: filters["type"] = type
    if user["role"] == "brand_admin":
        filters["$or"] = [{"brand_id": user.get("brand_id")}, {"related_entity": user.get("brand_id")}]
    return await list_docs("documents", filters, skip, limit)

@api.delete("/documents/{did}")
async def doc_delete(did: str, user: dict = Depends(require_role("super_admin"))):
    await db.documents.delete_one({"id": did})
    return {"ok": True}


# ---------- ASSET DIGITAL TWIN + HEALTH + VALUATION + IoT ----------
def _health_score(a: dict) -> dict:
    """Deterministic health score derived from asset attributes."""
    base = int(a.get("health", 100))
    cycles = int(a.get("charging_cycles", 0))
    age_days = 0
    if a.get("installation_date"):
        try: age_days = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(a["installation_date"])).days)
        except Exception: pass
    score = max(0, min(100, base - (cycles // 200) - (age_days // 180)))
    risk = "low" if score >= 80 else ("medium" if score >= 60 else ("high" if score >= 40 else "critical"))
    rul_years = round(max(0.0, (score / 100.0) * 5.0), 1)
    action = "Routine monitoring" if risk == "low" else ("Schedule inspection" if risk == "medium" else ("Preventive maintenance recommended" if risk == "high" else "Immediate service required"))
    return {"score": score, "risk": risk, "remaining_useful_life_years": rul_years, "recommended_action": action}

def _valuation(a: dict) -> dict:
    purchase = float(a.get("purchase_price", 0) or 0)
    landed = purchase + float(a.get("installation_cost", 0) or 0) + float(a.get("insurance", 0) or 0) + float(a.get("iot_cost", 0) or 0)
    hs = _health_score(a)["score"]
    current_value = round(landed * (0.3 + 0.7 * hs / 100), 2)
    revenue = float(a.get("revenue_generated", 0) or 0)
    maint = float(a.get("maintenance_cost", 0) or 0)
    lifetime_profit = round(revenue - maint - landed + current_value, 2)
    roi = round((lifetime_profit / landed * 100) if landed else 0, 1)
    return {"landed_cost": landed, "current_value": current_value, "lifetime_profit": lifetime_profit, "roi_percent": roi}

@api.get("/assets/{aid}/twin")
async def asset_twin(aid: str, user: dict = Depends(get_current_user)):
    a = await db.assets.find_one({"id": aid}, {"_id": 0})
    if not a: raise HTTPException(404, "Asset not found")
    health = _health_score(a)
    val = _valuation(a)
    # IoT abstract layer
    iot = {
        "asset_health": health["score"],
        "utilization_percent": a.get("utilization", 72),
        "failure_risk": health["risk"],
        "remaining_life_years": health["remaining_useful_life_years"],
        "service_required": health["risk"] in ("high", "critical"),
        "charging_behaviour": "Normal" if health["score"] >= 70 else "Irregular",
        "daily_backup_hours": a.get("daily_backup_hours", 4.2),
        "monthly_runtime_hours": a.get("monthly_runtime_hours", 126),
        "temperature_c": a.get("temperature", 32),
        "charging_cycles": a.get("charging_cycles", 0),
    }
    # Lifecycle timeline
    stages = ["procured", "warehouse", "assigned", "installed", "activated", "revenue_generating", "maintenance", "recovered", "refurbished", "redeployed", "retired"]
    tl_map = a.get("timeline", {}) or {}
    if a.get("created_at"): tl_map.setdefault("procured", a["created_at"])
    if a.get("status") != "in_inventory": tl_map.setdefault("warehouse", a.get("created_at"))
    if a.get("outlet_id"): tl_map.setdefault("assigned", a.get("installation_date"))
    if a.get("installation_date"):
        tl_map.setdefault("installed", a["installation_date"])
        tl_map.setdefault("activated", a["installation_date"])
        tl_map.setdefault("revenue_generating", a["installation_date"])
    if a.get("status") == "maintenance": tl_map.setdefault("maintenance", now_iso())
    if a.get("status") == "retired": tl_map.setdefault("recovered", now_iso())
    timeline = [{"stage": s, "at": tl_map.get(s)} for s in stages]
    return {"asset": a, "health": health, "valuation": val, "iot": iot, "timeline": timeline}


# ---------- CUSTOMER RISK ENGINE ----------
@api.get("/brands/{brand_id}/risk")
async def brand_risk(brand_id: str, user: dict = Depends(require_role("super_admin", "brand_admin"))):
    if user["role"] == "brand_admin" and user.get("brand_id") != brand_id:
        raise HTTPException(403, "Forbidden")
    invs = await db.invoices.find({"brand_id": brand_id}).to_list(500)
    overdue = sum(1 for i in invs if i.get("status") in ("pending", "overdue"))
    paid = sum(1 for i in invs if i.get("status") == "paid")
    total = len(invs) or 1
    payment_ratio = paid / total
    tickets = await db.maintenance_tickets.count_documents({"brand_id": brand_id, "status": {"$in": ["open", "assigned"]}})
    score = 100 - int((1 - payment_ratio) * 60) - min(20, tickets * 4) - min(20, overdue * 3)
    score = max(0, min(100, score))
    tier = "low" if score >= 80 else ("medium" if score >= 60 else ("high" if score >= 40 else "critical"))
    return {"brand_id": brand_id, "score": score, "tier": tier, "payment_ratio": round(payment_ratio, 2), "open_tickets": tickets, "overdue_invoices": overdue}


# ---------- CONTROL TOWER (extended dashboard) ----------
@api.get("/dashboard/control-tower")
async def control_tower(user: dict = Depends(require_role("super_admin"))):
    total_assets = await db.assets.count_documents({})
    installed = await db.assets.count_documents({"status": "installed"})
    inventory = await db.assets.count_documents({"status": "in_inventory"})
    maint_assets = await db.assets.count_documents({"status": "maintenance"})
    retired = await db.assets.count_documents({"status": "retired"})

    invs_paid = await db.invoices.aggregate([{"$match": {"status": "paid"}}, {"$group": {"_id": None, "t": {"$sum": "$total"}, "g": {"$sum": "$gst_amount"}, "n": {"$sum": 1}}}]).to_list(1)
    invs_pending = await db.invoices.aggregate([{"$match": {"status": {"$in": ["pending", "overdue"]}}}, {"$group": {"_id": None, "t": {"$sum": "$total"}, "n": {"$sum": 1}}}]).to_list(1)
    invoice_collected = invs_paid[0]["t"] if invs_paid else 0
    gst_collected = invs_paid[0]["g"] if invs_paid else 0
    outstanding = invs_pending[0]["t"] if invs_pending else 0
    total_invoiced = invoice_collected + outstanding
    collection_efficiency = round((invoice_collected / total_invoiced * 100), 1) if total_invoiced else 100

    # MRR from active subscriptions
    mrr = 0.0
    async for sub in db.subscriptions.find({"status": "active"}):
        plan = await db.subscription_plans.find_one({"id": sub["plan_id"]})
        if plan: mrr += plan["monthly_price"]

    # Health distribution
    buckets = {"excellent": 0, "good": 0, "fair": 0, "poor": 0}
    async for a in db.assets.find({}):
        s = _health_score(a)["score"]
        if s >= 85: buckets["excellent"] += 1
        elif s >= 70: buckets["good"] += 1
        elif s >= 50: buckets["fair"] += 1
        else: buckets["poor"] += 1
    health_dist = [{"band": k, "count": v} for k, v in buckets.items()]

    # SLAs — synthetic from ticket + install data
    open_tk = await db.maintenance_tickets.count_documents({"status": {"$in": ["open", "assigned"]}})
    resolved_tk = await db.maintenance_tickets.count_documents({"status": {"$in": ["resolved", "closed"]}})
    maint_sla = round((resolved_tk / (resolved_tk + open_tk) * 100), 1) if (resolved_tk + open_tk) else 100
    installs_done = await db.outlets.count_documents({"installation_status": "installed"})
    installs_total = await db.outlets.count_documents({})
    install_sla = round((installs_done / installs_total * 100), 1) if installs_total else 100

    return {
        "business": {
            "active_brands": await db.brands.count_documents({"status": "active"}),
            "active_outlets": await db.outlets.count_documents({"status": "active"}),
            "active_assets": installed,
            "available_inventory": inventory,
            "assets_under_installation": await db.outlets.count_documents({"installation_status": "scheduled"}),
            "assets_under_maintenance": maint_assets,
            "warranty_claims": await db.warranty_claims.count_documents({"approval_status": "pending"}),
            "active_subscriptions": await db.subscriptions.count_documents({"status": "active"}),
        },
        "financial": {
            "mrr": mrr, "arr": mrr * 12, "outstanding": outstanding,
            "invoice_collected": invoice_collected, "gst_collected": gst_collected,
            "collection_efficiency": collection_efficiency,
        },
        "portfolio": {
            "total_aum": total_assets, "active": installed, "idle": inventory,
            "recovered": retired, "redeployed": 0, "health_distribution": health_dist,
        },
        "operational": {
            "installation_sla_percent": install_sla,
            "maintenance_sla_percent": maint_sla,
            "warranty_resolution_days_avg": 3.2,
            "asset_utilization_percent": 74,
            "avg_battery_health": round(sum(b["count"] * w for b, w in zip(health_dist, [92, 78, 60, 40])) / max(total_assets, 1), 1),
            "avg_backup_hours": 4.4,
        },
    }



# ---------- SEED ----------
async def seed_data():
    # Ensure indexes
    await db.users.create_index("email", unique=True)
    await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.brands.create_index("email")
    await db.outlets.create_index("brand_id")
    await db.assets.create_index("serial_number", unique=True)

    admin_email = os.environ.get("ADMIN_EMAIL", "admin@rushgro.com")
    admin_pw = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "id": new_id(), "email": admin_email, "password_hash": hash_password(admin_pw),
            "name": "RushGro Super Admin", "phone": "+919999900000",
            "role": "super_admin", "status": "active", "created_at": now_iso(),
        })
    else:
        if not verify_password(admin_pw, existing["password_hash"]):
            await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_pw)}})

    # Seed subscription plans
    if await db.subscription_plans.count_documents({}) == 0:
        plans = [
            {"id": new_id(), "name": "FlexiPod 5.5 kW", "capacity_kw": 5.5, "monthly_price": 7000, "gst_percent": 18, "description": "Standard backup plan for small QSR outlets", "status": "active", "created_at": now_iso()},
            {"id": new_id(), "name": "FlexiPod 10.5 kW", "capacity_kw": 10.5, "monthly_price": 11000, "gst_percent": 18, "description": "High-capacity backup for cloud kitchens & mid-size stores", "status": "active", "created_at": now_iso()},
        ]
        await db.subscription_plans.insert_many(plans)

    # Seed a demo manufacturer, brand, outlet, users
    if await db.manufacturers.count_documents({}) == 0:
        mfr_id = new_id()
        await db.manufacturers.insert_one({
            "id": mfr_id, "name": "Amaron Batteries Pvt Ltd", "contact_person": "Rakesh Gupta",
            "email": "sales@amaron.example", "phone": "+911140001234", "address": "Sector 44",
            "city": "Gurugram", "gst": "06AAACA1234H1Z2", "website": "https://amaron.example",
            "inventory_available": 42, "contract_status": "active", "created_at": now_iso(),
        })
        mfr2 = new_id()
        await db.manufacturers.insert_one({
            "id": mfr2, "name": "Exide Energy Storage", "contact_person": "Sunita Rao",
            "email": "biz@exide.example", "phone": "+912233445566", "address": "Ballard Estate",
            "city": "Mumbai", "gst": "27AAECE9876N1ZP", "website": "https://exide.example",
            "inventory_available": 30, "contract_status": "active", "created_at": now_iso(),
        })

        brand_id = new_id()
        await db.brands.insert_one({
            "id": brand_id, "name": "Chai Point", "logo_url": None, "gst_number": "29AAACC1234K1ZQ",
            "pan": "AAACC1234K", "email": "ops@chaipoint.example", "phone": "+918040001111",
            "address": "MG Road", "city": "Bangalore", "state": "Karnataka", "pincode": "560001",
            "primary_contact": "Priya Nair", "subscription_plan_id": None, "status": "active",
            "created_at": now_iso(),
        })
        brand2 = new_id()
        await db.brands.insert_one({
            "id": brand2, "name": "Rebel Foods", "logo_url": None, "gst_number": "27AAACR9999L1Z5",
            "pan": "AAACR9999L", "email": "ceo@rebelfoods.example", "phone": "+912299887766",
            "address": "Andheri West", "city": "Mumbai", "state": "Maharashtra", "pincode": "400058",
            "primary_contact": "Kabir Shah", "subscription_plan_id": None, "status": "active",
            "created_at": now_iso(),
        })

        outlet_id = new_id()
        await db.outlets.insert_one({
            "id": outlet_id, "brand_id": brand_id, "name": "Chai Point - Indiranagar", "code": "CP-BLR-001",
            "address": "100ft Rd", "state": "Karnataka", "city": "Bangalore", "pincode": "560038",
            "power_requirement_kw": 5.5, "expected_backup_hours": 4, "store_type": "QSR",
            "contact_person": "Manoj Kumar", "phone": "+919845123456", "email": "indiranagar@chaipoint.example",
            "status": "active", "installation_status": "installed", "created_at": now_iso(),
        })
        outlet2 = new_id()
        await db.outlets.insert_one({
            "id": outlet2, "brand_id": brand_id, "name": "Chai Point - Koramangala", "code": "CP-BLR-002",
            "address": "80ft Rd", "state": "Karnataka", "city": "Bangalore", "pincode": "560095",
            "power_requirement_kw": 10.5, "expected_backup_hours": 6, "store_type": "QSR",
            "contact_person": "Anita Rao", "phone": "+919845998877", "email": "kora@chaipoint.example",
            "status": "active", "installation_status": "scheduled", "created_at": now_iso(),
        })
        outlet3 = new_id()
        await db.outlets.insert_one({
            "id": outlet3, "brand_id": brand2, "name": "Faasos - Powai", "code": "RB-MUM-001",
            "address": "Hiranandani", "state": "Maharashtra", "city": "Mumbai", "pincode": "400076",
            "power_requirement_kw": 10.5, "expected_backup_hours": 5, "store_type": "Cloud Kitchen",
            "contact_person": "Rahul Verma", "phone": "+919820123123", "email": "powai@rebel.example",
            "status": "active", "installation_status": "installed", "created_at": now_iso(),
        })

        # Assets
        plan_55 = await db.subscription_plans.find_one({"capacity_kw": 5.5})
        plan_105 = await db.subscription_plans.find_one({"capacity_kw": 10.5})
        assets = [
            {"id": new_id(), "serial_number": "FP-A55-000001", "manufacturer_id": mfr_id, "model": "FlexiPod 5.5", "capacity_kw": 5.5, "voltage": 48,
             "warranty_start": now_iso(), "warranty_end": (datetime.now(timezone.utc)+timedelta(days=730)).isoformat(),
             "outlet_id": outlet_id, "brand_id": brand_id, "installation_date": now_iso(),
             "health": 96, "status": "installed", "remarks": "", "created_at": now_iso()},
            {"id": new_id(), "serial_number": "FP-A105-000101", "manufacturer_id": mfr2, "model": "FlexiPod 10.5", "capacity_kw": 10.5, "voltage": 96,
             "warranty_start": now_iso(), "warranty_end": (datetime.now(timezone.utc)+timedelta(days=730)).isoformat(),
             "outlet_id": outlet3, "brand_id": brand2, "installation_date": now_iso(),
             "health": 88, "status": "installed", "remarks": "", "created_at": now_iso()},
            {"id": new_id(), "serial_number": "FP-A55-000002", "manufacturer_id": mfr_id, "model": "FlexiPod 5.5", "capacity_kw": 5.5, "voltage": 48,
             "warranty_start": None, "warranty_end": None,
             "outlet_id": None, "brand_id": None, "installation_date": None,
             "health": 100, "status": "in_inventory", "remarks": "New stock", "created_at": now_iso()},
        ]
        await db.assets.insert_many(assets)

        # Subscriptions & invoices for the two installed assets
        for a in assets[:2]:
            plan = plan_55 if a["capacity_kw"] == 5.5 else plan_105
            sub_id = new_id()
            await db.subscriptions.insert_one({
                "id": sub_id, "brand_id": a["brand_id"], "outlet_id": a["outlet_id"], "asset_id": a["id"],
                "plan_id": plan["id"], "start_date": now_iso(),
                "next_billing_date": (datetime.now(timezone.utc)+timedelta(days=15)).isoformat(),
                "status": "active", "created_at": now_iso(),
            })
            inv_no = f"INV-{datetime.now(timezone.utc).strftime('%Y%m')}-{new_id()[:6].upper()}"
            subtotal = plan["monthly_price"]
            gst = round(subtotal * plan["gst_percent"] / 100, 2)
            await db.invoices.insert_one({
                "id": new_id(), "invoice_number": inv_no, "brand_id": a["brand_id"], "outlet_id": a["outlet_id"],
                "subscription_id": sub_id, "plan_name": plan["name"],
                "subtotal": subtotal, "gst_amount": gst, "total": subtotal+gst,
                "status": "paid", "paid_at": now_iso(),
                "due_date": (datetime.now(timezone.utc)+timedelta(days=7)).isoformat(),
                "created_at": now_iso(),
            })
            # pending next invoice
            await db.invoices.insert_one({
                "id": new_id(), "invoice_number": f"INV-{datetime.now(timezone.utc).strftime('%Y%m')}-{new_id()[:6].upper()}",
                "brand_id": a["brand_id"], "outlet_id": a["outlet_id"],
                "subscription_id": sub_id, "plan_name": plan["name"],
                "subtotal": subtotal, "gst_amount": gst, "total": subtotal+gst,
                "status": "pending", "paid_at": None,
                "due_date": (datetime.now(timezone.utc)+timedelta(days=15)).isoformat(),
                "created_at": now_iso(),
            })

        # Demo users for other portals
        demo_users = [
            {"id": new_id(), "email": "brand@chaipoint.example", "password_hash": hash_password("Brand@12345"),
             "name": "Priya Nair", "phone": "+918040001111", "role": "brand_admin", "brand_id": brand_id,
             "status": "active", "created_at": now_iso()},
            {"id": new_id(), "email": "outlet@chaipoint.example", "password_hash": hash_password("Outlet@12345"),
             "name": "Manoj Kumar", "phone": "+919845123456", "role": "outlet_user", "brand_id": brand_id,
             "outlet_id": outlet_id, "status": "active", "created_at": now_iso()},
            {"id": new_id(), "email": "engineer@rushserv.example", "password_hash": hash_password("Service@12345"),
             "name": "Vikram Singh", "phone": "+919845000001", "role": "rushserv_user",
             "status": "active", "created_at": now_iso()},
            {"id": new_id(), "email": "mfr@amaron.example", "password_hash": hash_password("Mfg@12345"),
             "name": "Rakesh Gupta", "phone": "+911140001234", "role": "manufacturer_user",
             "manufacturer_id": mfr_id, "status": "active", "created_at": now_iso()},
        ]
        await db.users.insert_many(demo_users)

    # Phase 2 seed data (independent guards, run once even after phase 1 ran)
    if await db.capital_partners.count_documents({}) == 0:
        await db.capital_partners.insert_many([
                {"id": new_id(), "name": "Northern Arc NBFC", "contact_person": "Ravi Krishnan", "email": "ravi@northernarc.example",
                 "phone": "+919876500001", "capital_type": "NBFC", "total_commitment": 50000000, "capital_deployed": 32000000,
                 "available_capital": 18000000, "interest_rate": 12.5, "tenure_months": 36,
                 "next_payout_date": (datetime.now(timezone.utc)+timedelta(days=15)).isoformat(),
                 "status": "active", "created_at": now_iso()},
                {"id": new_id(), "name": "Zerodha Family Office", "contact_person": "Nithin Rao", "email": "nithin@zfo.example",
                 "phone": "+919876500002", "capital_type": "Family Office", "total_commitment": 30000000, "capital_deployed": 12000000,
                 "available_capital": 18000000, "interest_rate": 9.5, "tenure_months": 60,
                 "next_payout_date": (datetime.now(timezone.utc)+timedelta(days=30)).isoformat(),
                 "status": "active", "created_at": now_iso()},
            ])
    if await db.asset_pools.count_documents({}) == 0:
        await db.asset_pools.insert_one({
                "id": new_id(), "name": "Pool-Alpha-2026-Q1", "total_capital": 15000000, "number_of_assets": 2,
                "current_value": 14200000, "total_revenue": 890000, "expected_yield_percent": 14.5,
                "investor_ids": [], "asset_ids": [], "created_at": now_iso(),
            })

    # Demo tickets & warranty (guarded independently)
    if await db.maintenance_tickets.count_documents({}) == 0:
        any_asset = await db.assets.find_one({"status": "installed"})
        if any_asset:
            await db.maintenance_tickets.insert_one({
                "id": new_id(), "ticket_id": f"TKT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-DEMO1",
                "brand_id": any_asset.get("brand_id"), "outlet_id": any_asset.get("outlet_id"), "asset_id": any_asset["id"],
                "issue": "Battery not switching to backup automatically",
                "priority": "high", "assigned_engineer": None, "visit_date": None,
                "status": "open", "notes": "", "photos": [], "created_at": now_iso(),
            })
    if await db.warranty_claims.count_documents({}) == 0:
        any_asset = await db.assets.find_one({"status": "installed"})
        if any_asset:
            await db.warranty_claims.insert_one({
                "id": new_id(), "claim_id": f"WCM-{datetime.now(timezone.utc).strftime('%Y%m%d')}-DEMO1",
                "asset_id": any_asset["id"], "manufacturer_id": any_asset.get("manufacturer_id"),
                "brand_id": any_asset.get("brand_id"), "outlet_id": any_asset.get("outlet_id"),
                "description": "Cell degradation observed at 88% health after 6 months",
                "documents": [], "approval_status": "pending", "warranty_status": "under_warranty",
                "created_at": now_iso(),
            })


@app.on_event("startup")
async def startup():
    await seed_data()
    log.info("RushGro PBaaS seeded and ready.")


@app.on_event("shutdown")
async def shutdown():
    client.close()


app.include_router(api)

# ---------- IoT Integration (Flexi Twin) ----------
from integrations.iot.router import make_iot_router
iot_router = make_iot_router(get_current_user, db)
api2 = APIRouter(prefix="/api")
api2.include_router(iot_router)
app.include_router(api2)

# CORS
cors_origins = os.environ.get("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
<<<<<<< HEAD
    allow_origins=[
        "http://localhost:3000",
        "https://rushgro.com",
        "https://www.rushgro.com"
    ],
    allow_credentials=True,
=======
    allow_origins=cors_origins if cors_origins != ["*"] else ["*"],
    allow_credentials=True if cors_origins != ["*"] else False,
>>>>>>> 44609dc27a2cba9e555700853b69d60983a7439f
    allow_methods=["*"],
    allow_headers=["*"],
)
