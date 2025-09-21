from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from pymongo import MongoClient
from typing import Optional
from pydantic import BaseModel
from bson import ObjectId
import os
from dotenv import load_dotenv
from fastapi import Request
from fastapi import Depends
from fastapi import File, UploadFile, Form
from fastapi.staticfiles import StaticFiles
import shutil
from typing import List
from pydantic import EmailStr
from fastapi import Form, File, UploadFile
from typing import List
from fastapi import Query




# Load env variables
load_dotenv()

MONGO_URI = "mongodb://admin:Aayush2004@localhost:27017/sanskriti?authSource=admin"
SECRET_KEY = "q7d1JpL4wW2tqjK9eYx0Fnm3bR6sUhG5Zc8kMv2pAt7rXoDyVf9hQnB1jS4lT0X"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# MongoDB client
client = MongoClient(MONGO_URI)
db = client["sanskriti"]
admin_collection = db["admin"]
users_collection = db["users"]
events_collection = db["events"]
products_collection = db["products"]
orders_collection = db["orders"]
messages_collection = db["messages"]
embedding_collection = db["embedding"]
gallery_collection = db["gallery"]





# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="admin/login")

# FastAPI app
app = FastAPI()
# Serve uploaded files
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


# Enable CORS (open to all origins for now)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------
# Utility functions
# ------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_current_admin(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    email = payload.get("email")
    admin = admin_collection.find_one({"email": email})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return admin

# ------------------------
# Models
# ------------------------
class AdminRegister(BaseModel):
    name: str
    email: str
    mobile: str
    password: str

class AdminUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    mobile: Optional[str] = None
    password: Optional[str] = None

# ------------------------
# Routes
# ------------------------

class UserRegister(BaseModel):
    name: str
    email: str
    mobile: str
    address: str
    password: str   # ✅ added

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    mobile: Optional[str] = None
    address: Optional[str] = None
    password: Optional[str] = None   # ✅ allow update

from fastapi import Body

# ------------------------
# User Login (manual, google=False)
# ------------------------
@app.post("/users/login")
def user_login(email: str = Body(...), password: str = Body(...)):
    user = users_collection.find_one({"email": email, "google": False})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": str(user["_id"]), "email": user["email"]})
    return {
    "access_token": token,
    "token_type": "bearer",
    "email": user["email"],
    "name": user["name"],
    "mobile": user.get("mobile"),
    "address": user.get("address"),
    "profilePic": user.get("profilePic"),  # ✅ will be None if not set
    "google": False,
    "event": user.get("event", False)
    }


# Register new user (admin only)
@app.post("/users/register")
def register_user(user: UserRegister, current_admin=Depends(get_current_admin)):
    existing = users_collection.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    hashed_pw = hash_password(user.password)

    users_collection.insert_one({
        "name": user.name,
        "email": user.email,
        "mobile": user.mobile,
        "address": user.address,
        "password": hashed_pw,   # ✅ store hashed password
        "google": False,         # ✅ mark as manual signup
    })
    return {"message": "User registered successfully"}

# List users (admin only)
@app.get("/users/list")
def list_users(current_admin=Depends(get_current_admin)):
    users = list(users_collection.find({}, {"password": 0}))
    for u in users:
        u["_id"] = str(u["_id"])
    return {"users": users}

# Update user (admin only)
@app.put("/users/update/{user_id}")
def update_user(user_id: str, update: UserUpdate, current_admin=Depends(get_current_admin)):
    updates = {k: v for k, v in update.dict().items() if v is not None}

    if "password" in updates:
        if updates["password"].strip() == "":
            updates.pop("password")   # ignore empty password
        else:
            updates["password"] = hash_password(updates["password"])

    result = users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User updated successfully"}

# Delete user (admin only)
@app.delete("/users/delete/{user_id}")
def delete_user(user_id: str, current_admin=Depends(get_current_admin)):
    result = users_collection.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}


@app.post("/auth/google")
async def google_auth(request: Request):
    data = await request.json()
    email = data.get("email")
    name = data.get("name")

    if not email:
        raise HTTPException(status_code=400, detail="Email missing from Google response")

    print("🔹 [START] google_auth called for:", email)

    user = users_collection.find_one({"email": email})

    if not user:
        print("👤 New Google user, inserting...")
        users_collection.insert_one({
            "name": name,
            "email": email,
            "google": True,
        })
        user = users_collection.find_one({"email": email})  # ✅ re-fetch
    else:
        print("✅ Existing Google user found:", user.get("_id"))
        if "google" not in user:
            users_collection.update_one({"email": email}, {"$set": {"google": True}})
            user["google"] = True

    token = create_access_token({"email": email})
    print("🎉 Google auth successful for:", email)

    return {
        "access_token": token,
        "token_type": "bearer",
        "email": user["email"],
        "name": user.get("name"),
        "mobile": user.get("mobile"),
        "address": user.get("address"),
        "profilePic": user.get("profilePic"),
        "google": True,
        "event": user.get("event", False)
    }

# 1️⃣ Login (open)
@app.post("/admin/login")
def admin_login(form_data: OAuth2PasswordRequestForm = Depends()):
    admin = admin_collection.find_one({"email": form_data.username})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(form_data.password, admin["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": str(admin["_id"]), "email": admin["email"]})
    return {"access_token": token, "token_type": "bearer"}

# 2️⃣ Register new admin (protected)
@app.post("/admin/register")
def register_admin(admin: AdminRegister, current_admin=Depends(get_current_admin)):
    existing = admin_collection.find_one({"email": admin.email})
    if existing:
        raise HTTPException(status_code=400, detail="Admin with this email already exists")

    hashed_pw = hash_password(admin.password)
    admin_collection.insert_one({
        "name": admin.name,
        "email": admin.email,
        "mobile": admin.mobile,
        "password": hashed_pw
    })
    return {"message": "Admin registered successfully"}

# 3️⃣ List all admins (protected)
@app.get("/admin/list")
def list_admins(current_admin=Depends(get_current_admin)):
    admins = list(admin_collection.find({}, {"password": 0}))
    for admin in admins:
        admin["_id"] = str(admin["_id"])
    return {"admins": admins}

# 4️⃣ Update admin (protected)
@app.put("/admin/update/{admin_id}")
def update_admin(admin_id: str, update: AdminUpdate, current_admin=Depends(get_current_admin)):
    updates = {k: v for k, v in update.dict().items() if v is not None}
    # ⚠️ Only update password if it is non-empty
    if "password" in updates:
        if updates["password"].strip() == "":
            updates.pop("password")  # ignore empty password
        else:
            updates["password"] = hash_password(updates["password"])

    result = admin_collection.update_one({"_id": ObjectId(admin_id)}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Admin not found")
    return {"message": "Admin updated successfully"}

# 5️⃣ Delete admin (protected)
@app.delete("/admin/delete/{admin_id}")
def delete_admin(admin_id: str, current_admin=Depends(get_current_admin)):
    result = admin_collection.delete_one({"_id": ObjectId(admin_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Admin not found")
    return {"message": "Admin deleted successfully"}

# 6️⃣ Get profile (protected)
@app.get("/admin/profile")
def get_profile(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    email = payload.get("email")
    admin = admin_collection.find_one({"email": email}, {"_id": 0, "password": 0})
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return {"profile": admin}

# 7️⃣ Self-register first admin (open, only if DB empty)
@app.post("/admin/self-register")
def self_register(admin: AdminRegister):
    if admin_collection.count_documents({}) > 0:
        raise HTTPException(status_code=403, detail="Self-register only allowed when no admin exists")
    hashed_pw = hash_password(admin.password)
    admin_collection.insert_one({
        "name": admin.name,
        "email": admin.email,
        "mobile": admin.mobile,
        "password": hashed_pw
    })
    return {"message": "First admin created successfully"}

import json

@app.put("/users/update-profile")
async def update_profile(
    mobile: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
    embedding: Optional[str] = Form(None),   # comes as JSON string
    profilePic: Optional[UploadFile] = File(None),
    token: str = Depends(oauth2_scheme)
):
    # Decode token
    payload = decode_token(token)
    email = payload.get("email")
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    updates = {}

    if mobile:
        updates["mobile"] = mobile
    if address:
        updates["address"] = address

    # ✅ Save profilePic
    # ✅ Save profilePic
    if profilePic:
        file_ext = profilePic.filename.split(".")[-1].lower()
        file_name = f"{str(user['_id'])}_{int(datetime.utcnow().timestamp())}.{file_ext}"
        file_path = f"uploads/{file_name}"

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(profilePic.file, buffer)

        img_url = f"/uploads/{file_name}"
        updates["profilePic"] = img_url

        # 🚨 Enforce embedding with profilePic
        if not embedding:
            raise HTTPException(status_code=400, detail="Face embedding required when uploading profile picture")


    # ✅ Save embedding (safe JSON parse + link to user_id)
    if embedding:
        try:
            embedding_array = json.loads(embedding)   # safe JSON parse
            if not isinstance(embedding_array, list):
                raise ValueError("Embedding must be a list")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid embedding format")

        updates["embedding"] = embedding_array

        embedding_collection.update_one(
            {"user_id": str(user["_id"])},
            {
                "$set": {
                    "user_id": str(user["_id"]),
                    "embedding": embedding_array,
                    "profilePic": updates.get("profilePic")
                }
            },
            upsert=True
        )


    users_collection.update_one({"_id": user["_id"]}, {"$set": updates})

    return {"message": "Profile updated successfully", "updates": updates}


class EventCreate(BaseModel):
    name: str
    status: bool
    entryFee: float
    startDate: str  # store as ISO string (e.g., "2025-10-15")
    endDate: str

@app.post("/events/add")
def add_event(event: EventCreate, current_admin=Depends(get_current_admin)):
    new_event = {
        "name": event.name,
        "status": event.status,
        "entryFee": event.entryFee,
        "startDate": event.startDate,
        "endDate": event.endDate,
       
    }
    result = events_collection.insert_one(new_event)
    new_event["_id"] = str(result.inserted_id)
    return {"message": "Event added successfully", "event": new_event}

# Public route → list all events
@app.get("/events/list")
def list_events():
    events = list(db["events"].find({}))
    for e in events:
        e["_id"] = str(e["_id"])  # convert main _id
        # Convert ObjectId inside members list (if exists)
        if "members" in e:
            e["members"] = [str(uid) for uid in e["members"]]
    return {"events": events}


@app.get("/users/unregistered")
def list_unregistered_users():
    # Users where "event" does not exist OR is False
    users = list(users_collection.find(
        {"$or": [{"event": {"$exists": False}}, {"event": False}]},
        {"name": 1, "mobile": 1}  # only return name & mobile
    ))

    for u in users:
        u["_id"] = str(u["_id"])
    return {"users": users}



class RegisterMembersRequest(BaseModel):
    user_ids: List[str]

@app.post("/events/{event_id}/register-members")
def register_members(event_id: str, req: RegisterMembersRequest, current_admin=Depends(get_current_admin)):
    event = db["events"].find_one({"_id": ObjectId(event_id)})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Convert string ids to ObjectId
    object_ids = [ObjectId(uid) for uid in req.user_ids]

    # 1️⃣ Add users into event's members array
    db["events"].update_one(
        {"_id": ObjectId(event_id)},
        {"$addToSet": {"members": {"$each": object_ids}}}  # ensures no duplicates
    )

    # 2️⃣ Update users → mark event=True
    db["users"].update_many(
        {"_id": {"$in": object_ids}},
        {"$set": {"event": True}}
    )

    return {"message": f"{len(object_ids)} members registered successfully"}


@app.get("/events/{event_id}/members")
def get_event_members(event_id: str, current_admin=Depends(get_current_admin)):
    event = db["events"].find_one({"_id": ObjectId(event_id)})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    member_ids = event.get("members", [])
    users = list(users_collection.find({"_id": {"$in": member_ids}}, {"name": 1, "mobile": 1}))
    for u in users:
        u["_id"] = str(u["_id"])
    return {"members": users}

@app.delete("/events/{event_id}/remove-member/{user_id}")
def remove_member(event_id: str, user_id: str, current_admin=Depends(get_current_admin)):
    event = db["events"].find_one({"_id": ObjectId(event_id)})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # 1️⃣ Remove from event document
    db["events"].update_one(
        {"_id": ObjectId(event_id)},
        {"$pull": {"members": ObjectId(user_id)}}
    )

    # 2️⃣ Update user → set event=False
    db["users"].update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"event": False}}
    )

    return {"message": "Member removed successfully"}


class EventUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[bool] = None
    entryFee: Optional[float] = None
    startDate: Optional[str] = None
    endDate: Optional[str] = None

@app.put("/events/update/{event_id}")
def update_event(event_id: str, update: EventUpdate, current_admin=Depends(get_current_admin)):
    updates = {k: v for k, v in update.dict().items() if v is not None}
    result = events_collection.update_one({"_id": ObjectId(event_id)}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Event not found")
    updated_event = events_collection.find_one({"_id": ObjectId(event_id)})
    updated_event["_id"] = str(updated_event["_id"])
    return {"message": "Event updated successfully", "event": updated_event}


@app.delete("/events/{event_id}")
def delete_event(event_id: str, current_admin=Depends(get_current_admin)):
    event = events_collection.find_one({"_id": ObjectId(event_id)})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # 1️⃣ Get all registered members
    member_ids = event.get("members", [])

    if member_ids:
        # Ensure ObjectIds
        object_ids = [uid if isinstance(uid, ObjectId) else ObjectId(uid) for uid in member_ids]

        # 2️⃣ Update users → mark event=False
        users_collection.update_many(
            {"_id": {"$in": object_ids}},
            {"$set": {"event": False}}
        )

    # 3️⃣ Delete event
    events_collection.delete_one({"_id": ObjectId(event_id)})

    return {"message": "Event deleted successfully and members updated"}


@app.post("/users/register-event")
def user_register_event(token: str = Depends(oauth2_scheme)):
    """
    Allows a logged-in user to self-register for an event (get their pass).
    - Marks user.event = True
    - Optionally: you can also add them to the latest active event automatically
    """
    payload = decode_token(token)
    email = payload.get("email")

    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 1️⃣ Check if already registered
    if user.get("event") is True:
        return {"message": "User already has an event pass"}

    # 2️⃣ Find the latest active event
    event = events_collection.find_one(
        {"status": True},
        sort=[("startDate", -1)]  # latest event
    )
    if not event:
        raise HTTPException(status_code=404, detail="No active event available")

    # 3️⃣ Add user into event's members list
    events_collection.update_one(
        {"_id": event["_id"]},
        {"$addToSet": {"members": user["_id"]}}
    )

    # 4️⃣ Update user → set event=True
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"event": True}}
    )

    return {"message": "Pass registered successfully", "event_id": str(event["_id"])}



# ------------------------
# Scan Operators
# ------------------------

scan_collection = db["scan"]

class ScanRegister(BaseModel):
    email: str
    password: str

class ScanOut(BaseModel):
    _id: str
    email: str

@app.post("/scan/register")
def register_scan(scan: ScanRegister, current_admin=Depends(get_current_admin)):
    existing = scan_collection.find_one({"email": scan.email})
    if existing:
        raise HTTPException(status_code=400, detail="Scan user already exists")

    hashed_pw = hash_password(scan.password)
    scan_collection.insert_one({
        "email": scan.email,
        "password": hashed_pw
    })
    return {"message": "Scan user created successfully"}

@app.get("/scan/list")
def list_scans(current_admin=Depends(get_current_admin)):
    scans = list(scan_collection.find({}, {"password": 0}))  # don’t return passwords
    for s in scans:
        s["_id"] = str(s["_id"])
    return {"scans": scans}


@app.post("/scan/verify")
def verify_scan(token: str = Body(..., embed=True)):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": False}  # ignore expiry
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # 🔑 Find user
    user = None
    if "sub" in payload:
        user_id = payload["sub"]
        try:
            user = users_collection.find_one({"_id": ObjectId(user_id)})
        except Exception:
            user = users_collection.find_one({"_id": user_id})  # fallback string
    elif "email" in payload:
        user = users_collection.find_one({"email": payload["email"]})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # ✅ Check event registration
    if not user.get("event", False):
        return {"status": "denied", "message": "User not registered for event"}

    # ✅ Handle visit flag
    if "visit" not in user:
        # first scan → set visit true, then flip to false
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"visit": False}}
        )
        visit_allowed = True
    else:
        if user["visit"] is False:
            # already visited
            return {"status": "denied", "message": "User already visited"}
        else:
            # visit is true → allow entry, set to false
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"visit": False}}
            )
            visit_allowed = True

    if visit_allowed:
        return {
            "status": "success",
            "name": user.get("name"),
            "mobile": user.get("mobile"),
            "profilePic": user.get("profilePic"),
        }


@app.post("/scan/login")
def scan_login(email: str = Body(...), password: str = Body(...)):
    scan_user = scan_collection.find_one({"email": email})
    if not scan_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(password, scan_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": str(scan_user["_id"]), "email": scan_user["email"]})

    return {
        "access_token": token,
        "token_type": "bearer",
        "email": scan_user["email"]
    }


# -------------------------
# Helpers
# -------------------------
def serialize_product(p):
    return {
        "_id": str(p["_id"]),
        "name": p["name"],
        "price": p["price"]
    }

def serialize_order(o):
    return {
        "_id": str(o.get("_id")),   # ✅ include ObjectId for React key & expand toggle
        "orderId": o.get("orderId"),
        "name": o["user"]["name"],
        "email": o["user"]["email"],
        "mobile": o["user"]["mobile"],
        "orders": o["items"],
        "taken": o.get("taken", False),
        "createdAt": o.get("createdAt").isoformat() if o.get("createdAt") else None  # ✅ include createdAt
    }


# -------------------------
# Product Models
# -------------------------
class ProductCreate(BaseModel):
    name: str
    price: float

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = None

# -------------------------
# Order Models
# -------------------------
class OrderItem(BaseModel):
    product: str
    quantity: int

class OrderCreate(BaseModel):
    orderId: str
    name: str
    email: str
    mobile: str
    items: List[OrderItem]

# -------------------------
# Routes: Products
# -------------------------
@app.post("/products")
def add_product(product: ProductCreate):
    new_product = {
        "name": product.name,
        "price": product.price,
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow()
    }
    result = products_collection.insert_one(new_product)
    return {"message": "Product added", "product": serialize_product(new_product)}

@app.get("/products")
def list_products():
    products = list(products_collection.find())
    return {"products": [serialize_product(p) for p in products]}

@app.put("/products/{product_id}")
def update_product(product_id: str, update: ProductUpdate):
    updates = {k: v for k, v in update.dict().items() if v is not None}
    updates["updatedAt"] = datetime.utcnow()
    result = products_collection.update_one({"_id": ObjectId(product_id)}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product updated"}

@app.delete("/products/{product_id}")
def delete_product(product_id: str):
    result = products_collection.delete_one({"_id": ObjectId(product_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted"}

# -------------------------
# Routes: Orders
# -------------------------
@app.post("/orders")
def create_order(order: OrderCreate):
    new_order = {
        "orderId": order.orderId,
        "user": {
            "name": order.name,
            "email": order.email,
            "mobile": order.mobile
        },
        "items": [item.dict() for item in order.items],
        "taken": False,
        "createdAt": datetime.utcnow()
    }
    orders_collection.insert_one(new_order)
    return {"message": "Order created", "order": serialize_order(new_order)}

@app.get("/orders")
def list_orders():
    orders = list(orders_collection.find())
    return {"orders": [serialize_order(o) for o in orders]}

@app.put("/orders/{orderId}/toggle-taken")
def toggle_taken(orderId: str):
    order = orders_collection.find_one({"orderId": orderId})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    new_status = not order.get("taken", False)
    orders_collection.update_one({"orderId": orderId}, {"$set": {"taken": new_status}})
    return {"message": f"Order marked as {'taken' if new_status else 'not taken'}"}

@app.delete("/orders/clear-taken")
def clear_taken_orders():
    result = orders_collection.delete_many({"taken": True})
    return {"message": f"{result.deleted_count} taken orders deleted"}

@app.delete("/orders/clear-all")
def clear_all_orders():
    result = orders_collection.delete_many({})
    return {"message": f"{result.deleted_count} orders deleted"}


@app.get("/orders/my-orders")
def get_my_orders(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    email = payload.get("email")
    print("Decoded email:", email)

    orders = list(orders_collection.find({"user.email": {"$regex": f"^{email}$", "$options": "i"}}))
    print("Found orders:", orders)

    return {"orders": [serialize_order(o) for o in orders]}


class MessageCreate(BaseModel):
    email: EmailStr
    createdAt: Optional[datetime] = None


@app.post("/messages")
def create_message(message: MessageCreate):
    new_message = {
        "email": message.email,
        "createdAt": datetime.utcnow()
    }
    result = messages_collection.insert_one(new_message)
    new_message["_id"] = str(result.inserted_id)
    return {"message": "Message saved successfully", "data": new_message}


@app.get("/messages")
def list_messages(current_admin=Depends(get_current_admin)):
    messages = list(messages_collection.find({}))
    for m in messages:
        m["_id"] = str(m["_id"])
    return {"messages": messages}



@app.get("/embeddings")
def list_embeddings():
    docs = list(embedding_collection.find({}))
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"embeddings": docs}



@app.post("/gallery/save")
async def save_gallery(
    title: str = Form(...),
    date: str = Form(...),
    images: List[UploadFile] = File(...),
    metadata: List[str] = Form(...),  # comes as JSON string list
):
    saved_images = []
    for i, image in enumerate(images):
        file_ext = image.filename.split(".")[-1].lower()
        file_name = f"gallery_{datetime.utcnow().timestamp()}_{i}.{file_ext}"
        file_path = f"uploads/{file_name}"

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)

        meta = json.loads(metadata[i])  # parse per-image metadata

        saved_images.append({
            "filePath": f"/uploads/{file_name}",
            "type": meta["type"],
            "faces": meta.get("faces", []),
        })

    gallery_doc = {
        "title": title,
        "date": date,
        "images": saved_images,
        
    }
    result = gallery_collection.insert_one(gallery_doc)
    gallery_doc["_id"] = str(result.inserted_id)

    return {"message": "Gallery saved successfully", "gallery": gallery_doc}


@app.get("/gallery")
def list_gallery(page: int = 0, limit: int = 20):
    skip = page * limit
    cursor = gallery_collection.find().skip(skip).limit(limit).sort("_id", -1)

    image_urls = []
    for g in cursor:
        for img in g.get("images", []):
            image_urls.append({"url": img["filePath"]})

    return {"images": image_urls}


@app.get("/users/me/embedding")
def get_my_embedding(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    email = payload.get("email")
    print("Decoded payload:", payload)
    print("Email from token:", email)


    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    emb = embedding_collection.find_one({"user_id": str(user["_id"])})
    if not emb:
        raise HTTPException(status_code=404, detail="No embedding found for this user")

    emb["_id"] = str(emb["_id"])
    return {"embedding": emb["embedding"], "profilePic": emb.get("profilePic")}


@app.get("/gallery/with-faces")
def list_gallery_with_faces(page: int = 0, limit: int = 50):
    """
    Returns gallery images including face embeddings for AI search.
    Use this ONLY for face recognition, not normal gallery browsing.
    """
    skip = page * limit
    cursor = gallery_collection.find().skip(skip).limit(limit).sort("_id", -1)

    images_with_faces = []
    for g in cursor:
        for img in g.get("images", []):
            images_with_faces.append({
                "url": img["filePath"],
                "type": img.get("type"),
                "faces": img.get("faces", []),  # ✅ descriptors included
            })

    return {"images": images_with_faces}



@app.post("/gallery/filter")
def filter_gallery(
    titles: Optional[List[str]] = Body(default=[]),
    dateFrom: Optional[str] = Body(default=None),
    dateTo: Optional[str] = Body(default=None),
):
    query = {}

    if titles:
        query["title"] = {"$in": titles}

    if dateFrom and dateTo:
        query["date"] = {"$gte": dateFrom, "$lte": dateTo}
    elif dateFrom:
        query["date"] = {"$gte": dateFrom}
    elif dateTo:
        query["date"] = {"$lte": dateTo}

    results = gallery_collection.find(query).sort("date", -1)

    image_urls = []
    for g in results:
        for img in g.get("images", []):
            image_urls.append({
                "url": img["filePath"],
                "title": g.get("title"),
                "date": g.get("date"),
            })

    return {"images": image_urls}

@app.get("/gallery/titles")
def list_gallery_titles():
    titles = gallery_collection.distinct("title")  # MongoDB distinct query
    return {"titles": titles}
