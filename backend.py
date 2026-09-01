from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt as pyjwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ.get('JWT_SECRET', 'dev-secret')
JWT_ALGO = 'HS256'
ACCESS_MINUTES = 60 * 24 * 7  # 7 days

app = FastAPI()
api = APIRouter(prefix="/api")
bearer = HTTPBearer(auto_error=False)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def uid() -> str:
    return str(uuid.uuid4())

# ============ MODELS ============
class SignupIn(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=6)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: Literal["customer", "admin"]
    phone: Optional[str] = None
    avatar: Optional[str] = None

class TokenOut(BaseModel):
    access_token: str
    user: UserOut

class BookIn(BaseModel):
    title: str
    author: str
    description: str
    category: str
    price: float
    discount_price: Optional[float] = None
    stock: int = 0
    isbn: Optional[str] = None
    publisher: Optional[str] = None
    publication_date: Optional[str] = None
    language: str = "English"
    pages: int = 0
    format: str = "Paperback"
    cover_image: Optional[str] = None
    featured: bool = False
    bestseller: bool = False
    new_arrival: bool = False

class BookOut(BookIn):
    id: str
    rating: float = 0.0
    review_count: int = 0
    created_at: str

class CartItemIn(BaseModel):
    book_id: str
    quantity: int = 1

class AddressIn(BaseModel):
    full_name: str
    phone: str
    address_line: str
    city: str
    state: str
    postal_code: str
    country: str = "India"
    address_type: str = "Home"

class ReviewIn(BaseModel):
    rating: int = Field(ge=1, le=5)
    review_text: str

class CouponIn(BaseModel):
    code: str
    discount_type: Literal["percent", "fixed"]
    discount_value: float
    minimum_order: float = 0
    expiry_date: Optional[str] = None
    usage_limit: int = 1000
    active: bool = True

class CheckoutIn(BaseModel):
    address_id: str
    payment_method: Literal["UPI", "Card", "NetBanking", "COD"]
    coupon_code: Optional[str] = None

class OrderStatusIn(BaseModel):
    order_status: Literal["Pending","Confirmed","Processing","Packed","Shipped","Out for Delivery","Delivered","Cancelled"]

# ============ AUTH HELPERS ============
def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_pw(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

def make_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "role": user["role"],
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_MINUTES),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

async def current_user(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> dict:
    if not cred:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = pyjwt.decode(cred.credentials, JWT_SECRET, algorithms=[JWT_ALGO])
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        if not user:
            raise HTTPException(401, "User not found")
        return user
    except pyjwt.PyJWTError:
        raise HTTPException(401, "Invalid token")

async def admin_only(user: dict = Depends(current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    return user

def to_user_out(u: dict) -> UserOut:
    return UserOut(id=u["id"], name=u["name"], email=u["email"], role=u["role"], phone=u.get("phone"), avatar=u.get("avatar"))

# ============ AUTH ROUTES ============
@api.post("/auth/signup", response_model=TokenOut)
async def signup(body: SignupIn):
    email = body.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(409, "Email already registered")
    user = {
        "id": uid(),
        "name": body.name.strip(),
        "email": email,
        "password_hash": hash_pw(body.password),
        "role": "customer",
        "phone": None,
        "avatar": None,
        "created_at": now_iso(),
    }
    await db.users.insert_one(user)
    return TokenOut(access_token=make_token(user), user=to_user_out(user))

@api.post("/auth/login", response_model=TokenOut)
async def login(body: LoginIn):
    email = body.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not verify_pw(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    return TokenOut(access_token=make_token(user), user=to_user_out(user))

@api.get("/auth/me", response_model=UserOut)
async def me(user=Depends(current_user)):
    return to_user_out(user)

@api.put("/auth/me", response_model=UserOut)
async def update_me(body: dict, user=Depends(current_user)):
    updates = {k: v for k, v in body.items() if k in ("name", "phone", "avatar")}
    if updates:
        await db.users.update_one({"id": user["id"]}, {"$set": updates})
    updated = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    return to_user_out(updated)

# ============ BOOKS ============
@api.get("/books")
async def list_books(
    q: Optional[str] = None,
    category: Optional[str] = None,
    author: Optional[str] = None,
    format: Optional[str] = None,
    language: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    min_rating: Optional[float] = None,
    featured: Optional[bool] = None,
    bestseller: Optional[bool] = None,
    new_arrival: Optional[bool] = None,
    sort: Optional[str] = "relevance",
    limit: int = 100,
    skip: int = 0,
):
    query = {}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"author": {"$regex": q, "$options": "i"}},
            {"isbn": {"$regex": q, "$options": "i"}},
            {"category": {"$regex": q, "$options": "i"}},
            {"publisher": {"$regex": q, "$options": "i"}},
        ]
    if category: query["category"] = category
    if author: query["author"] = {"$regex": author, "$options": "i"}
    if format: query["format"] = format
    if language: query["language"] = language
    if featured is not None: query["featured"] = featured
    if bestseller is not None: query["bestseller"] = bestseller
    if new_arrival is not None: query["new_arrival"] = new_arrival
    price_q = {}
    if min_price is not None: price_q["$gte"] = min_price
    if max_price is not None: price_q["$lte"] = max_price
    if price_q: query["price"] = price_q
    if min_rating is not None: query["rating"] = {"$gte": min_rating}

    cursor = db.books.find(query, {"_id": 0})
    sort_map = {
        "price_asc": [("price", 1)],
        "price_desc": [("price", -1)],
        "rating": [("rating", -1)],
        "popular": [("review_count", -1)],
        "newest": [("created_at", -1)],
    }
    if sort in sort_map:
        cursor = cursor.sort(sort_map[sort])
    books = await cursor.skip(skip).limit(limit).to_list(limit)
    return books

@api.get("/books/categories")
async def categories():
    cats = await db.books.distinct("category")
    return sorted(cats)

@api.get("/books/{book_id}")
async def get_book(book_id: str):
    book = await db.books.find_one({"id": book_id}, {"_id": 0})
    if not book:
        raise HTTPException(404, "Book not found")
    return book

@api.get("/books/{book_id}/related")
async def related_books(book_id: str):
    book = await db.books.find_one({"id": book_id}, {"_id": 0})
    if not book:
        return []
    related = await db.books.find(
        {"id": {"$ne": book_id}, "$or": [{"category": book["category"]}, {"author": book["author"]}]},
        {"_id": 0},
    ).limit(8).to_list(8)
    return related

@api.post("/admin/books")
async def create_book(body: BookIn, admin=Depends(admin_only)):
    book = body.dict()
    book["id"] = uid()
    book["rating"] = 0.0
    book["review_count"] = 0
    book["created_at"] = now_iso()
    await db.books.insert_one(book.copy())
    return {k: v for k, v in book.items() if k != "_id"}

@api.put("/admin/books/{book_id}")
async def update_book(book_id: str, body: dict, admin=Depends(admin_only)):
    body.pop("id", None); body.pop("_id", None)
    await db.books.update_one({"id": book_id}, {"$set": body})
    b = await db.books.find_one({"id": book_id}, {"_id": 0})
    return b

@api.delete("/admin/books/{book_id}")
async def delete_book(book_id: str, admin=Depends(admin_only)):
    await db.books.delete_one({"id": book_id})
    return {"ok": True}

# ============ CART ============
@api.get("/cart")
async def get_cart(user=Depends(current_user)):
    items = await db.cart_items.find({"user_id": user["id"]}, {"_id": 0}).to_list(1000)
    result = []
    for it in items:
        book = await db.books.find_one({"id": it["book_id"]}, {"_id": 0})
        if book:
            result.append({**it, "book": book})
    return result

@api.post("/cart")
async def add_to_cart(body: CartItemIn, user=Depends(current_user)):
    book = await db.books.find_one({"id": body.book_id}, {"_id": 0})
    if not book:
        raise HTTPException(404, "Book not found")
    if book["stock"] < body.quantity:
        raise HTTPException(400, f"Only {book['stock']} in stock")
    existing = await db.cart_items.find_one({"user_id": user["id"], "book_id": body.book_id})
    if existing:
        new_qty = existing["quantity"] + body.quantity
        if new_qty > book["stock"]:
            raise HTTPException(400, f"Only {book['stock']} in stock")
        await db.cart_items.update_one({"id": existing["id"]}, {"$set": {"quantity": new_qty}})
    else:
        await db.cart_items.insert_one({
            "id": uid(), "user_id": user["id"], "book_id": body.book_id, "quantity": body.quantity,
        })
    return {"ok": True}

@api.put("/cart/{book_id}")
async def update_cart(book_id: str, body: CartItemIn, user=Depends(current_user)):
    book = await db.books.find_one({"id": book_id}, {"_id": 0})
    if not book: raise HTTPException(404, "Book not found")
    if body.quantity <= 0:
        await db.cart_items.delete_one({"user_id": user["id"], "book_id": book_id})
    else:
        if body.quantity > book["stock"]:
            raise HTTPException(400, f"Only {book['stock']} in stock")
        await db.cart_items.update_one(
            {"user_id": user["id"], "book_id": book_id},
            {"$set": {"quantity": body.quantity}}, upsert=True,
        )
    return {"ok": True}

@api.delete("/cart/{book_id}")
async def remove_cart(book_id: str, user=Depends(current_user)):
    await db.cart_items.delete_one({"user_id": user["id"], "book_id": book_id})
    return {"ok": True}

# ============ WISHLIST ============
@api.get("/wishlist")
async def get_wishlist(user=Depends(current_user)):
    items = await db.wishlist.find({"user_id": user["id"]}, {"_id": 0}).to_list(1000)
    result = []
    for it in items:
        book = await db.books.find_one({"id": it["book_id"]}, {"_id": 0})
        if book:
            result.append({**it, "book": book})
    return result

@api.post("/wishlist/{book_id}")
async def add_wishlist(book_id: str, user=Depends(current_user)):
    exists = await db.wishlist.find_one({"user_id": user["id"], "book_id": book_id})
    if not exists:
        await db.wishlist.insert_one({"id": uid(), "user_id": user["id"], "book_id": book_id})
    return {"ok": True}

@api.delete("/wishlist/{book_id}")
async def del_wishlist(book_id: str, user=Depends(current_user)):
    await db.wishlist.delete_one({"user_id": user["id"], "book_id": book_id})
    return {"ok": True}

# ============ ADDRESSES ============
@api.get("/addresses")
async def list_addresses(user=Depends(current_user)):
    return await db.addresses.find({"user_id": user["id"]}, {"_id": 0}).to_list(100)

@api.post("/addresses")
async def add_address(body: AddressIn, user=Depends(current_user)):
    doc = body.dict()
    doc["id"] = uid(); doc["user_id"] = user["id"]
    await db.addresses.insert_one(doc.copy())
    return {k: v for k, v in doc.items() if k != "_id"}

@api.put("/addresses/{aid}")
async def edit_address(aid: str, body: AddressIn, user=Depends(current_user)):
    await db.addresses.update_one({"id": aid, "user_id": user["id"]}, {"$set": body.dict()})
    return {"ok": True}

@api.delete("/addresses/{aid}")
async def del_address(aid: str, user=Depends(current_user)):
    await db.addresses.delete_one({"id": aid, "user_id": user["id"]})
    return {"ok": True}

# ============ COUPONS ============
@api.post("/coupons/validate")
async def validate_coupon(body: dict, user=Depends(current_user)):
    code = body.get("code", "").upper()
    subtotal = float(body.get("subtotal", 0))
    coupon = await db.coupons.find_one({"code": code, "active": True}, {"_id": 0})
    if not coupon:
        raise HTTPException(404, "Invalid coupon")
    if subtotal < coupon["minimum_order"]:
        raise HTTPException(400, f"Minimum order Rs.{coupon['minimum_order']}")
    if coupon["discount_type"] == "percent":
        discount = subtotal * coupon["discount_value"] / 100
    else:
        discount = coupon["discount_value"]
    return {"coupon": coupon, "discount": round(discount, 2)}

@api.get("/coupons")
async def list_coupons(admin=Depends(admin_only)):
    return await db.coupons.find({}, {"_id": 0}).to_list(200)

@api.post("/admin/coupons")
async def create_coupon(body: CouponIn, admin=Depends(admin_only)):
    doc = body.dict()
    doc["code"] = doc["code"].upper()
    doc["id"] = uid()
    await db.coupons.insert_one(doc.copy())
    return {k: v for k, v in doc.items() if k != "_id"}

# ============ ORDERS ============
DELIVERY_FEE = 40.0

@api.post("/checkout")
async def checkout(body: CheckoutIn, user=Depends(current_user)):
    address = await db.addresses.find_one({"id": body.address_id, "user_id": user["id"]}, {"_id": 0})
    if not address:
        raise HTTPException(404, "Address not found")
    cart_items = await db.cart_items.find({"user_id": user["id"]}, {"_id": 0}).to_list(1000)
    if not cart_items:
        raise HTTPException(400, "Cart empty")

    subtotal = 0.0
    order_items = []
    for ci in cart_items:
        book = await db.books.find_one({"id": ci["book_id"]}, {"_id": 0})
        if not book:
            raise HTTPException(400, "Book missing")
        if book["stock"] < ci["quantity"]:
            raise HTTPException(400, f"Not enough stock for {book['title']}")
        price = book.get("discount_price") or book["price"]
        subtotal += price * ci["quantity"]
        order_items.append({
            "id": uid(), "book_id": book["id"], "title": book["title"],
            "cover_image": book.get("cover_image"), "quantity": ci["quantity"], "price": price,
        })

    discount = 0.0
    if body.coupon_code:
        coupon = await db.coupons.find_one({"code": body.coupon_code.upper(), "active": True}, {"_id": 0})
        if coupon and subtotal >= coupon["minimum_order"]:
            if coupon["discount_type"] == "percent":
                discount = subtotal * coupon["discount_value"] / 100
            else:
                discount = coupon["discount_value"]

    delivery_fee = 0 if body.payment_method != "COD" and subtotal > 500 else DELIVERY_FEE
    total = round(subtotal - discount + delivery_fee, 2)

    order = {
        "id": uid(),
        "user_id": user["id"],
        "user_name": user["name"],
        "user_email": user["email"],
        "address": address,
        "items": order_items,
        "subtotal": round(subtotal, 2),
        "discount": round(discount, 2),
        "delivery_fee": delivery_fee,
        "total": total,
        "payment_method": body.payment_method,
        "payment_status": "Paid" if body.payment_method != "COD" else "Pending",
        "order_status": "Confirmed",
        "coupon_code": body.coupon_code,
        "created_at": now_iso(),
        "timeline": [
            {"status": "Order Placed", "at": now_iso()},
            {"status": "Confirmed", "at": now_iso()},
        ],
    }
    await db.orders.insert_one(order.copy())

    # Reduce stock, clear cart
    for oi in order_items:
        await db.books.update_one({"id": oi["book_id"]}, {"$inc": {"stock": -oi["quantity"]}})
    await db.cart_items.delete_many({"user_id": user["id"]})

    return {k: v for k, v in order.items() if k != "_id"}

@api.get("/orders")
async def my_orders(user=Depends(current_user)):
    return await db.orders.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)

@api.get("/orders/{order_id}")
async def get_order(order_id: str, user=Depends(current_user)):
    q = {"id": order_id}
    if user["role"] != "admin":
        q["user_id"] = user["id"]
    o = await db.orders.find_one(q, {"_id": 0})
    if not o: raise HTTPException(404, "Order not found")
    return o

@api.get("/admin/orders")
async def all_orders(admin=Depends(admin_only)):
    return await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)

@api.put("/admin/orders/{order_id}/status")
async def upd_order_status(order_id: str, body: OrderStatusIn, admin=Depends(admin_only)):
    await db.orders.update_one(
        {"id": order_id},
        {"$set": {"order_status": body.order_status},
         "$push": {"timeline": {"status": body.order_status, "at": now_iso()}}},
    )
    return await db.orders.find_one({"id": order_id}, {"_id": 0})

# ============ REVIEWS ============
async def _recalc_rating(book_id: str):
    reviews = await db.reviews.find({"book_id": book_id}, {"_id": 0}).to_list(1000)
    if reviews:
        avg = sum(r["rating"] for r in reviews) / len(reviews)
        await db.books.update_one({"id": book_id}, {"$set": {"rating": round(avg, 1), "review_count": len(reviews)}})
    else:
        await db.books.update_one({"id": book_id}, {"$set": {"rating": 0.0, "review_count": 0}})

@api.get("/books/{book_id}/reviews")
async def get_reviews(book_id: str):
    return await db.reviews.find({"book_id": book_id}, {"_id": 0}).sort("created_at", -1).to_list(200)

@api.post("/books/{book_id}/reviews")
async def add_review(book_id: str, body: ReviewIn, user=Depends(current_user)):
    existing = await db.reviews.find_one({"book_id": book_id, "user_id": user["id"]})
    if existing:
        await db.reviews.update_one(
            {"id": existing["id"]},
            {"$set": {"rating": body.rating, "review_text": body.review_text, "updated_at": now_iso()}},
        )
    else:
        await db.reviews.insert_one({
            "id": uid(), "book_id": book_id, "user_id": user["id"],
            "user_name": user["name"], "rating": body.rating, "review_text": body.review_text,
            "created_at": now_iso(), "updated_at": now_iso(),
        })
    await _recalc_rating(book_id)
    return {"ok": True}

@api.delete("/books/{book_id}/reviews")
async def del_review(book_id: str, user=Depends(current_user)):
    await db.reviews.delete_one({"book_id": book_id, "user_id": user["id"]})
    await _recalc_rating(book_id)
    return {"ok": True}

# ============ ADMIN DASHBOARD ============
@api.get("/admin/stats")
async def admin_stats(admin=Depends(admin_only)):
    orders = await db.orders.find({}, {"_id": 0}).to_list(10000)
    total_revenue = sum(o["total"] for o in orders)
    total_orders = len(orders)
    total_books = await db.books.count_documents({})
    total_customers = await db.users.count_documents({"role": "customer"})
    pending = sum(1 for o in orders if o["order_status"] in ("Pending","Confirmed","Processing","Packed"))
    low_stock = await db.books.count_documents({"stock": {"$lt": 5}})

    # revenue by category
    cat_map = {}
    for o in orders:
        for it in o["items"]:
            b = await db.books.find_one({"id": it["book_id"]}, {"_id": 0})
            if b:
                cat_map[b["category"]] = cat_map.get(b["category"], 0) + it["price"] * it["quantity"]

    # best sellers
    book_sales = {}
    for o in orders:
        for it in o["items"]:
            book_sales[it["book_id"]] = book_sales.get(it["book_id"], 0) + it["quantity"]
    best_ids = sorted(book_sales.items(), key=lambda x: -x[1])[:5]
    best_sellers = []
    for bid, qty in best_ids:
        b = await db.books.find_one({"id": bid}, {"_id": 0})
        if b: best_sellers.append({"title": b["title"], "sold": qty})

    return {
        "total_revenue": round(total_revenue, 2),
        "total_orders": total_orders,
        "total_books": total_books,
        "total_customers": total_customers,
        "pending_orders": pending,
        "low_stock_books": low_stock,
        "sales_by_category": [{"category": k, "revenue": round(v,2)} for k,v in cat_map.items()],
        "best_sellers": best_sellers,
    }

@api.get("/admin/customers")
async def all_customers(admin=Depends(admin_only)):
    users = await db.users.find({"role": "customer"}, {"_id": 0, "password_hash": 0}).to_list(1000)
    for u in users:
        os_list = await db.orders.find({"user_id": u["id"]}, {"_id": 0}).to_list(1000)
        u["order_count"] = len(os_list)
        u["total_spent"] = round(sum(o["total"] for o in os_list), 2)
    return users

# ============ NEWSLETTER ============
@api.post("/newsletter")
async def newsletter(body: dict):
    email = body.get("email","").lower().strip()
    if not email: raise HTTPException(400, "Email required")
    exists = await db.newsletter.find_one({"email": email})
    if not exists:
        await db.newsletter.insert_one({"id": uid(), "email": email, "created_at": now_iso()})
    return {"ok": True}

# ============ SEED ============
SEED_BOOKS = [
    ("The Midnight Library","Matt Haig","A dazzling novel about all the choices that go into a life well lived.","Fiction",499,349,25,True,True,False,"https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=600"),
    ("Atomic Habits","James Clear","Tiny changes, remarkable results — build good habits and break bad ones.","Self-Help",699,499,40,True,True,False,"https://images.unsplash.com/photo-1589998059171-988d887df646?w=600"),
    ("Deep Work","Cal Newport","Rules for focused success in a distracted world.","Self-Help",599,449,30,False,True,False,"https://images.unsplash.com/photo-1497633762265-9d179a990aa6?w=600"),
    ("The Silent Patient","Alex Michaelides","A shocking psychological thriller.","Mystery & Thriller",450,319,20,True,False,True,"https://images.unsplash.com/photo-1476275466078-4007374efbbe?w=600"),
    ("Project Hail Mary","Andy Weir","A lone astronaut must save humanity.","Science Fiction",799,599,15,True,True,False,"https://images.unsplash.com/photo-1518709268805-4e9042af9f23?w=600"),
    ("Dune","Frank Herbert","A stunning blend of adventure and mysticism.","Science Fiction",850,650,18,False,True,False,"https://images.unsplash.com/photo-1531901599143-df5010ab9438?w=600"),
    ("The Name of the Wind","Patrick Rothfuss","The tale of Kvothe, a wizard of legend.","Fantasy",750,549,22,True,False,False,"https://images.unsplash.com/photo-1512820790803-83ca734da794?w=600"),
    ("A Court of Thorns and Roses","Sarah J. Maas","A sweeping romantic fantasy.","Romance",650,469,35,False,True,True,"https://images.unsplash.com/photo-1543002588-bfa74002ed7e?w=600"),
    ("Rich Dad Poor Dad","Robert Kiyosaki","What the rich teach their kids about money.","Business & Finance",399,299,50,True,True,False,"https://images.unsplash.com/photo-1554260570-e9689a3418b8?w=600"),
    ("Zero to One","Peter Thiel","Notes on startups, or how to build the future.","Business & Finance",550,399,25,False,False,True,"https://images.unsplash.com/photo-1521587760476-6c12a4b040da?w=600"),
    ("Clean Code","Robert C. Martin","A handbook of agile software craftsmanship.","Programming",899,699,28,True,True,False,"https://images.unsplash.com/photo-1517694712202-14dd9538aa97?w=600"),
    ("The Pragmatic Programmer","David Thomas","Your journey to mastery.","Programming",950,749,20,False,True,False,"https://images.unsplash.com/photo-1555949963-aa79dcee981c?w=600"),
    ("Introduction to Algorithms","Cormen et al.","The definitive algorithms textbook.","Programming",1499,1199,12,False,False,False,"https://images.unsplash.com/photo-1516321318423-f06f85e504b3?w=600"),
    ("Python Crash Course","Eric Matthes","A hands-on introduction to programming.","Programming",699,499,45,True,True,False,"https://images.unsplash.com/photo-1526379095098-d400fd0bf935?w=600"),
    ("Hands-On Machine Learning","Aurélien Géron","Concepts and tools to build intelligent systems.","Data Science & AI",1299,999,18,True,True,False,"https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600"),
    ("Deep Learning","Ian Goodfellow","The definitive deep learning textbook.","Data Science & AI",1799,1399,10,False,False,False,"https://images.unsplash.com/photo-1620712943543-bcc4688e7485?w=600"),
    ("The Hundred-Page ML Book","Andriy Burkov","Machine learning concisely.","Data Science & AI",599,449,25,False,False,True,"https://images.unsplash.com/photo-1509228468518-180dd4864904?w=600"),
    ("Sapiens","Yuval Noah Harari","A brief history of humankind.","History",699,499,30,True,True,False,"https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?w=600"),
    ("Educated","Tara Westover","A memoir about growing up and self-invention.","Biography",550,399,22,False,True,False,"https://images.unsplash.com/photo-1495640388908-05fa85288e61?w=600"),
    ("Steve Jobs","Walter Isaacson","The exclusive biography.","Biography",799,599,15,False,False,False,"https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?w=600"),
    ("The Alchemist","Paulo Coelho","A magical fable about following your dreams.","Fiction",299,199,55,True,True,False,"https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=600"),
    ("1984","George Orwell","A dystopian classic.","Fiction",350,249,40,True,True,False,"https://images.unsplash.com/photo-1495640452828-3df6795cf69b?w=600"),
    ("To Kill a Mockingbird","Harper Lee","A timeless classic of American literature.","Fiction",425,299,32,False,True,False,"https://images.unsplash.com/photo-1519682337058-a94d519337bc?w=600"),
    ("Pride and Prejudice","Jane Austen","A novel of manners.","Romance",325,229,28,False,False,False,"https://images.unsplash.com/photo-1476275466078-4007374efbbe?w=600"),
    ("It Ends With Us","Colleen Hoover","A heart-wrenching contemporary romance.","Romance",499,349,45,True,True,True,"https://images.unsplash.com/photo-1543002588-bfa74002ed7e?w=600"),
    ("Gone Girl","Gillian Flynn","A twisted thriller of a marriage gone wrong.","Mystery & Thriller",520,389,20,False,True,False,"https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?w=600"),
    ("The Girl on the Train","Paula Hawkins","A gripping psychological thriller.","Mystery & Thriller",480,349,18,False,False,False,"https://images.unsplash.com/photo-1512820790803-83ca734da794?w=600"),
    ("Harry Potter and the Sorcerer's Stone","J.K. Rowling","The magical beginning.","Fantasy",699,499,60,True,True,False,"https://images.unsplash.com/photo-1621351183012-e2f9972dd9bf?w=600"),
    ("The Hobbit","J.R.R. Tolkien","A great adventure begins.","Fantasy",550,399,42,True,True,False,"https://images.unsplash.com/photo-1509266272358-7701da638078?w=600"),
    ("Thinking, Fast and Slow","Daniel Kahneman","Groundbreaking insight on the mind.","Self-Help",799,599,20,False,True,False,"https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?w=600"),
    ("The 7 Habits of Highly Effective People","Stephen Covey","Powerful lessons in personal change.","Self-Help",499,349,35,True,True,False,"https://images.unsplash.com/photo-1554260570-e9689a3418b8?w=600"),
    ("Ikigai","Héctor García","The Japanese secret to a long and happy life.","Self-Help",399,279,50,True,True,True,"https://images.unsplash.com/photo-1522199755839-a2bacb67c546?w=600"),
    ("The Lean Startup","Eric Ries","How today's entrepreneurs use continuous innovation.","Business & Finance",599,449,22,False,False,False,"https://images.unsplash.com/photo-1521587760476-6c12a4b040da?w=600"),
    ("Good to Great","Jim Collins","Why some companies make the leap.","Business & Finance",650,499,18,False,False,False,"https://images.unsplash.com/photo-1554260570-e9689a3418b8?w=600"),
    ("Wings of Fire","A.P.J. Abdul Kalam","An autobiography.","Biography",349,249,40,False,True,False,"https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?w=600"),
    ("Guns, Germs, and Steel","Jared Diamond","The fates of human societies.","History",750,549,15,False,False,False,"https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?w=600"),
    ("The Very Hungry Caterpillar","Eric Carle","A beloved children's classic.","Children's Books",299,199,60,False,True,False,"https://images.unsplash.com/photo-1512253022256-19f2c67e4c8d?w=600"),
    ("Charlotte's Web","E.B. White","A heartwarming tale of friendship.","Children's Books",399,279,45,False,False,False,"https://images.unsplash.com/photo-1512253022256-19f2c67e4c8d?w=600"),
    ("Watchmen","Alan Moore","A groundbreaking graphic novel.","Comics & Graphic Novels",899,699,12,False,False,False,"https://images.unsplash.com/photo-1608889825205-eebdb9fc5806?w=600"),
    ("Maus","Art Spiegelman","A Holocaust survivor's tale.","Comics & Graphic Novels",750,549,10,False,False,True,"https://images.unsplash.com/photo-1608889825205-eebdb9fc5806?w=600"),
    ("Milk and Honey","Rupi Kaur","A poetry collection.","Poetry",399,279,30,False,True,False,"https://images.unsplash.com/photo-1519682337058-a94d519337bc?w=600"),
    ("The Sun and Her Flowers","Rupi Kaur","A journey of wilting and blooming.","Poetry",425,299,25,False,False,True,"https://images.unsplash.com/photo-1519682337058-a94d519337bc?w=600"),
]

async def seed_data():
    if await db.books.count_documents({}) == 0:
        for row in SEED_BOOKS:
            title,author,desc,cat,price,dprice,stock,feat,best,new,cover = row
            await db.books.insert_one({
                "id": uid(), "title": title, "author": author, "description": desc,
                "category": cat, "price": float(price), "discount_price": float(dprice),
                "stock": stock, "isbn": f"978-{uuid.uuid4().hex[:10]}", "publisher": "BookVerse Press",
                "publication_date": "2023-01-01", "language": "English", "pages": 300,
                "format": "Paperback", "cover_image": cover, "rating": round(3.8 + (hash(title)%20)/20*1.2,1),
                "review_count": (hash(title)%80)+5, "featured": feat, "bestseller": best,
                "new_arrival": new, "created_at": now_iso(),
            })
        logger.info(f"Seeded {len(SEED_BOOKS)} books")
    if not await db.users.find_one({"email": "admin@bookverse.com"}):
        await db.users.insert_one({
            "id": uid(), "name": "Admin", "email": "admin@bookverse.com",
            "password_hash": hash_pw("admin123"), "role": "admin", "phone": None,
            "avatar": None, "created_at": now_iso(),
        })
        logger.info("Seeded admin user")
    if await db.coupons.count_documents({}) == 0:
        await db.coupons.insert_many([
            {"id": uid(), "code": "WELCOME10", "discount_type": "percent", "discount_value": 10,
             "minimum_order": 300, "expiry_date": None, "usage_limit": 1000, "active": True},
            {"id": uid(), "code": "BOOK50", "discount_type": "fixed", "discount_value": 50,
             "minimum_order": 500, "expiry_date": None, "usage_limit": 1000, "active": True},
            {"id": uid(), "code": "FEST40", "discount_type": "percent", "discount_value": 40,
             "minimum_order": 1000, "expiry_date": None, "usage_limit": 100, "active": True},
        ])
        logger.info("Seeded coupons")

# Register router
app.include_router(api)

app.add_middleware(
    CORSMiddleware, allow_credentials=True, allow_origins=["*"],
    allow_methods=["*"], allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def on_start():
    await seed_data()

@app.on_event("shutdown")
async def on_stop():
    client.close()
