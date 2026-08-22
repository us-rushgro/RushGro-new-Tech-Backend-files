"""Pydantic models and shared types for RushGro PBaaS."""
from datetime import datetime, timezone
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr, ConfigDict
import uuid


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------- Roles ----------
Role = Literal[
    "super_admin",
    "brand_admin",
    "outlet_user",
    "rushserv_user",
    "manufacturer_user",
]

# ---------- User ----------
class UserBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    email: EmailStr
    phone: Optional[str] = None
    role: Role
    brand_id: Optional[str] = None
    outlet_id: Optional[str] = None
    manufacturer_id: Optional[str] = None
    status: Literal["active", "inactive"] = "active"


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    status: Optional[Literal["active", "inactive"]] = None
    role: Optional[Role] = None
    brand_id: Optional[str] = None
    outlet_id: Optional[str] = None
    manufacturer_id: Optional[str] = None


class UserOut(UserBase):
    id: str
    created_at: str


# ---------- Brand ----------
class BrandBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    logo_url: Optional[str] = None
    gst_number: Optional[str] = None
    pan: Optional[str] = None
    email: EmailStr
    phone: str
    address: Optional[str] = ""
    city: str
    state: Optional[str] = ""
    pincode: Optional[str] = ""
    primary_contact: Optional[str] = ""
    subscription_plan_id: Optional[str] = None
    status: Literal["pending", "active", "suspended"] = "pending"


class BrandCreate(BrandBase):
    pass


class BrandUpdate(BaseModel):
    name: Optional[str] = None
    logo_url: Optional[str] = None
    gst_number: Optional[str] = None
    pan: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    pincode: Optional[str] = None
    primary_contact: Optional[str] = None
    subscription_plan_id: Optional[str] = None
    status: Optional[Literal["pending", "active", "suspended"]] = None


class BrandOut(BrandBase):
    id: str
    created_at: str


# ---------- Outlet ----------
class OutletBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    brand_id: str
    name: str
    code: Optional[str] = None
    address: str
    state: Optional[str] = ""
    city: str
    pincode: Optional[str] = ""
    power_requirement_kw: float = 5.5
    expected_backup_hours: float = 4.0
    store_type: Optional[str] = "QSR"
    contact_person: Optional[str] = ""
    phone: Optional[str] = ""
    email: Optional[str] = ""
    status: Literal["pending", "active", "suspended"] = "pending"
    installation_status: Literal["not_installed", "scheduled", "installed"] = "not_installed"


class OutletCreate(OutletBase):
    pass


class OutletUpdate(BaseModel):
    name: Optional[str] = None
    code: Optional[str] = None
    address: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None
    pincode: Optional[str] = None
    power_requirement_kw: Optional[float] = None
    expected_backup_hours: Optional[float] = None
    store_type: Optional[str] = None
    contact_person: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    status: Optional[Literal["pending", "active", "suspended"]] = None
    installation_status: Optional[Literal["not_installed", "scheduled", "installed"]] = None


class OutletOut(OutletBase):
    id: str
    created_at: str


# ---------- Manufacturer ----------
class ManufacturerBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    contact_person: Optional[str] = ""
    email: EmailStr
    phone: str
    address: Optional[str] = ""
    city: str
    gst: Optional[str] = ""
    website: Optional[str] = ""
    inventory_available: int = 0
    contract_status: Literal["active", "paused", "terminated"] = "active"


class ManufacturerCreate(ManufacturerBase):
    pass


class ManufacturerUpdate(BaseModel):
    name: Optional[str] = None
    contact_person: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    gst: Optional[str] = None
    website: Optional[str] = None
    inventory_available: Optional[int] = None
    contract_status: Optional[Literal["active", "paused", "terminated"]] = None


class ManufacturerOut(ManufacturerBase):
    id: str
    created_at: str


# ---------- Asset ----------
class AssetBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    serial_number: str
    manufacturer_id: str
    model: str = "FlexiPod 5.5"
    capacity_kw: float = 5.5
    voltage: float = 48.0
    warranty_start: Optional[str] = None
    warranty_end: Optional[str] = None
    outlet_id: Optional[str] = None
    brand_id: Optional[str] = None
    installation_date: Optional[str] = None
    health: int = 100
    status: Literal["in_inventory", "allocated", "installed", "maintenance", "retired"] = "in_inventory"
    remarks: Optional[str] = ""


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    serial_number: Optional[str] = None
    manufacturer_id: Optional[str] = None
    model: Optional[str] = None
    capacity_kw: Optional[float] = None
    voltage: Optional[float] = None
    warranty_start: Optional[str] = None
    warranty_end: Optional[str] = None
    outlet_id: Optional[str] = None
    brand_id: Optional[str] = None
    installation_date: Optional[str] = None
    health: Optional[int] = None
    status: Optional[Literal["in_inventory", "allocated", "installed", "maintenance", "retired"]] = None
    remarks: Optional[str] = None


class AssetOut(AssetBase):
    id: str
    created_at: str


# ---------- Subscription Plan ----------
class SubscriptionPlanBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str  # "FlexiPod 5.5 kW"
    capacity_kw: float
    monthly_price: float  # ₹ excluding GST
    gst_percent: float = 18.0
    description: Optional[str] = ""
    status: Literal["active", "inactive"] = "active"


class SubscriptionPlanCreate(SubscriptionPlanBase):
    pass


class SubscriptionPlanOut(SubscriptionPlanBase):
    id: str
    created_at: str


# ---------- Subscription ----------
class SubscriptionBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    brand_id: str
    outlet_id: str
    asset_id: Optional[str] = None
    plan_id: str
    start_date: str
    next_billing_date: Optional[str] = None
    status: Literal["active", "pending", "suspended", "cancelled", "overdue"] = "active"


class SubscriptionCreate(SubscriptionBase):
    pass


class SubscriptionOut(SubscriptionBase):
    id: str
    created_at: str


# ---------- Maintenance ----------
class MaintenanceBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    brand_id: str
    outlet_id: str
    asset_id: Optional[str] = None
    issue: str
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    assigned_engineer: Optional[str] = None
    visit_date: Optional[str] = None
    status: Literal["open", "assigned", "in_progress", "resolved", "closed"] = "open"
    notes: Optional[str] = ""
    photos: List[str] = Field(default_factory=list)


class MaintenanceCreate(MaintenanceBase):
    pass


class MaintenanceUpdate(BaseModel):
    issue: Optional[str] = None
    priority: Optional[Literal["low", "medium", "high", "critical"]] = None
    assigned_engineer: Optional[str] = None
    visit_date: Optional[str] = None
    status: Optional[Literal["open", "assigned", "in_progress", "resolved", "closed"]] = None
    notes: Optional[str] = None
    photos: Optional[List[str]] = None


class MaintenanceOut(MaintenanceBase):
    id: str
    ticket_id: str
    created_at: str


# ---------- Warranty ----------
class WarrantyBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    asset_id: str
    manufacturer_id: str
    brand_id: str
    outlet_id: str
    description: str
    documents: List[str] = Field(default_factory=list)
    approval_status: Literal["pending", "approved", "rejected"] = "pending"
    warranty_status: Literal["under_warranty", "expired"] = "under_warranty"


class WarrantyCreate(WarrantyBase):
    pass


class WarrantyUpdate(BaseModel):
    description: Optional[str] = None
    documents: Optional[List[str]] = None
    approval_status: Optional[Literal["pending", "approved", "rejected"]] = None
    warranty_status: Optional[Literal["under_warranty", "expired"]] = None


class WarrantyOut(WarrantyBase):
    id: str
    claim_id: str
    created_at: str


# ---------- Invoice ----------
class InvoiceOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    invoice_number: str
    brand_id: str
    outlet_id: str
    subscription_id: str
    plan_name: str
    subtotal: float
    gst_amount: float
    total: float
    status: Literal["pending", "paid", "overdue", "cancelled"]
    due_date: str
    paid_at: Optional[str] = None
    created_at: str


# ---------- Notification ----------
class NotificationOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: Optional[str] = None
    role: Optional[str] = None
    brand_id: Optional[str] = None
    title: str
    message: str
    type: str = "info"
    read: bool = False
    created_at: str


# ---------- Audit Log ----------
class AuditLogOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    action: str
    entity: str
    entity_id: Optional[str] = None
    details: Optional[str] = ""
    created_at: str
