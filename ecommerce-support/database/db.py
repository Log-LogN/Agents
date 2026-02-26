"""
database/db.py
--------------
PostgreSQL database for the E-Commerce Customer Support Multi-Agent System.

Tables (10):
  customers, products, orders, order_items,
  returns, refunds, payments, complaints, reviews, loyalty_history

Auto-creates the 'ecommerce_db' database if it doesn't exist.
Seeds rich realistic fake data on first run — immediately usable.
"""
import os
from datetime import date, timedelta, datetime
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()


# ── Connection ────────────────────────────────────────────────────────────────

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "ecommerce_db"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )


def create_database_if_not_exists():
    db_name = os.getenv("DB_NAME", "ecommerce_db")
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname="postgres",
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (db_name,))
    if not cur.fetchone():
        cur.execute(f'CREATE DATABASE "{db_name}"')
        print(f"[OK] Database '{db_name}' created.")
    cur.close()
    conn.close()


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db():
    create_database_if_not_exists()
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id             SERIAL PRIMARY KEY,
            name           TEXT NOT NULL,
            email          TEXT NOT NULL UNIQUE,
            address        TEXT,
            city           TEXT,
            loyalty_tier   TEXT DEFAULT 'bronze',
            loyalty_points INTEGER DEFAULT 0,
            created_at     TIMESTAMP DEFAULT NOW()
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id            SERIAL PRIMARY KEY,
            name          TEXT NOT NULL,
            sku           TEXT NOT NULL UNIQUE,
            category      TEXT NOT NULL,
            price         NUMERIC(10,2) NOT NULL,
            stock_qty     INTEGER DEFAULT 0,
            reorder_level INTEGER DEFAULT 10,
            description   TEXT,
            brand         TEXT
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id               SERIAL PRIMARY KEY,
            customer_email   TEXT NOT NULL,
            status           TEXT DEFAULT 'processing',
            total_amount     NUMERIC(10,2) NOT NULL,
            shipping_address TEXT,
            tracking_number  TEXT,
            carrier          TEXT,
            created_at       TIMESTAMP DEFAULT NOW(),
            shipped_at       TIMESTAMP,
            delivered_at     TIMESTAMP
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS order_items (
            id           SERIAL PRIMARY KEY,
            order_id     INTEGER REFERENCES orders(id),
            product_id   INTEGER REFERENCES products(id),
            quantity     INTEGER NOT NULL,
            unit_price   NUMERIC(10,2) NOT NULL,
            subtotal     NUMERIC(10,2) NOT NULL
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS returns (
            id             SERIAL PRIMARY KEY,
            order_id       INTEGER REFERENCES orders(id),
            customer_email TEXT NOT NULL,
            product_id     INTEGER REFERENCES products(id),
            reason         TEXT NOT NULL,
            status         TEXT DEFAULT 'pending',
            fraud_flag     BOOLEAN DEFAULT FALSE,
            fraud_reason   TEXT,
            initiated_at   TIMESTAMP DEFAULT NOW(),
            resolved_at    TIMESTAMP
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS refunds (
            id             SERIAL PRIMARY KEY,
            return_id      INTEGER REFERENCES returns(id),
            customer_email TEXT NOT NULL,
            amount         NUMERIC(10,2) NOT NULL,
            method         TEXT DEFAULT 'original_payment',
            status         TEXT DEFAULT 'pending',
            processed_at   TIMESTAMP
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id             SERIAL PRIMARY KEY,
            order_id       INTEGER REFERENCES orders(id),
            customer_email TEXT NOT NULL,
            amount         NUMERIC(10,2) NOT NULL,
            method         TEXT NOT NULL,
            status         TEXT DEFAULT 'completed',
            transaction_id TEXT,
            payment_date   TIMESTAMP DEFAULT NOW()
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id             SERIAL PRIMARY KEY,
            customer_email TEXT NOT NULL,
            order_id       INTEGER REFERENCES orders(id),
            type           TEXT NOT NULL,
            description    TEXT NOT NULL,
            status         TEXT DEFAULT 'open',
            priority       TEXT DEFAULT 'medium',
            escalated      BOOLEAN DEFAULT FALSE,
            resolution     TEXT,
            created_at     TIMESTAMP DEFAULT NOW(),
            resolved_at    TIMESTAMP
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id             SERIAL PRIMARY KEY,
            customer_email TEXT NOT NULL,
            product_id     INTEGER REFERENCES products(id),
            order_id       INTEGER REFERENCES orders(id),
            rating         INTEGER CHECK(rating BETWEEN 1 AND 5),
            comment        TEXT,
            response       TEXT,
            created_at     TIMESTAMP DEFAULT NOW()
        )""")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS loyalty_history (
            id             SERIAL PRIMARY KEY,
            customer_email TEXT NOT NULL,
            points_change  INTEGER NOT NULL,
            reason         TEXT NOT NULL,
            balance_after  INTEGER NOT NULL,
            created_at     TIMESTAMP DEFAULT NOW()
        )""")

    conn.commit()
    _seed(conn, cur)
    cur.close()
    conn.close()
    print("[OK] E-Commerce database initialized with full seed data.")


# ── Seed Data ─────────────────────────────────────────────────────────────────

def _seed(conn, cur):
    cur.execute("SELECT COUNT(*) FROM customers")
    if cur.fetchone()[0] > 0:
        print("[OK] Seed data already present - skipping.")
        return

    today = date.today()

    # ── Customers ─────────────────────────────────────────────────────
    customers = [
        ("Aarav Sharma",    "aarav.sharma@shop.com",    "12 MG Road",       "Mumbai",    "gold",   4250),
        ("Priya Mehta",     "priya.mehta@shop.com",     "45 Brigade Road",  "Bangalore", "silver", 1850),
        ("Rohan Verma",     "rohan.verma@shop.com",     "7 Park Street",    "Kolkata",   "bronze", 320),
        ("Sneha Patel",     "sneha.patel@shop.com",     "88 Residency Rd",  "Pune",      "gold",   6100),
        ("Karan Gupta",     "karan.gupta@shop.com",     "22 Anna Salai",    "Chennai",   "silver", 2400),
        ("Anjali Nair",     "anjali.nair@shop.com",     "5 Connaught Pl",   "Delhi",     "platinum",9800),
        ("Vikram Singh",    "vikram.singh@shop.com",    "34 Linking Road",  "Mumbai",    "bronze", 150),
        ("Meena Joshi",     "meena.joshi@shop.com",     "18 FC Road",       "Pune",      "silver", 3200),
        ("Arjun Das",       "arjun.das@shop.com",       "99 Jubilee Hills", "Hyderabad", "gold",   5500),
        ("Kavya Reddy",     "kavya.reddy@shop.com",     "12 Koramangala",   "Bangalore", "bronze", 80),
        ("Serial Returner", "serial.returner@shop.com", "Unknown Address",  "Delhi",     "bronze", 0),
        ("Fraud Customer",  "fraud.customer@shop.com",  "Fake Street 1",    "Mumbai",    "bronze", 0),
    ]
    cur.executemany(
        "INSERT INTO customers(name,email,address,city,loyalty_tier,loyalty_points) VALUES(%s,%s,%s,%s,%s,%s)",
        customers
    )

    # ── Products ──────────────────────────────────────────────────────
    products = [
        ("Sony WH-1000XM5 Headphones",   "SONY-WH5-BLK", "Electronics",  29999, 45,  5,  "Industry-leading noise cancelling headphones with 30hr battery",       "Sony"),
        ("Samsung 65\" QLED TV",          "SAM-TV65-4K",  "Electronics", 129999, 8,   2,  "65-inch QLED 4K Smart TV with Quantum Processor",                     "Samsung"),
        ("Nike Air Max 270",             "NIKE-AM270-10", "Footwear",     8999, 120, 15,  "Lightweight running shoes with Max Air unit in heel",                  "Nike"),
        ("Levi's 511 Slim Fit Jeans",    "LEVIS-511-32",  "Apparel",      3499, 200, 20,  "Classic slim fit jeans in dark wash denim",                           "Levis"),
        ("Apple iPhone 15 Pro",          "APPLE-IP15P",   "Electronics", 134999, 22,  3,  "6.1-inch Super Retina XDR display, A17 Pro chip, titanium design",    "Apple"),
        ("Prestige Electric Kettle",     "PRES-KETTLE2",  "Kitchen",      1299,  85, 10,  "1.5L electric kettle with auto shut-off, 1500W",                      "Prestige"),
        ("Fastrack Analog Watch",        "FAST-W-ANA21",  "Accessories",  2499, 160, 25,  "Classic analog wristwatch with leather strap",                        "Fastrack"),
        ("Wildcraft 45L Backpack",       "WILD-BP45-GRN", "Bags",         2999,  55, 10,  "45 litre trekking backpack with rain cover",                          "Wildcraft"),
        ("Nestlé KitKat Gift Box 24pc",  "NESTLE-KK-24",  "Food",          699, 300, 50,  "Assorted KitKat chocolate gift box, 24 pieces",                       "Nestle"),
        ("Lenovo IdeaPad 3 Laptop",      "LEN-IP3-15",    "Electronics",  45999, 15,  3,  "15.6-inch FHD, AMD Ryzen 5, 8GB RAM, 512GB SSD",                      "Lenovo"),
        ("Bosch Hand Blender",           "BOSCH-HB-450",  "Kitchen",      2199,  42,  8,  "450W hand blender with 3-speed control and turbo function",            "Bosch"),
        ("Out-of-Stock Speaker",         "JBL-FLIP7-BLK", "Electronics",  8499,  0,   5,  "JBL Flip 7 Bluetooth speaker — currently out of stock",               "JBL"),
    ]
    cur.executemany(
        "INSERT INTO products(name,sku,category,price,stock_qty,reorder_level,description,brand) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
        products
    )

    # Get product IDs
    cur.execute("SELECT id, sku FROM products ORDER BY id")
    prod_ids = {r[1]: r[0] for r in cur.fetchall()}

    # ── Orders ────────────────────────────────────────────────────────
    def make_tracking():
        import random, string
        return "IND" + "".join(random.choices(string.digits, k=8))

    orders_raw = [
        # (email, status, total, addr, carrier, days_ago, shipped_ago, delivered_ago)
        ("aarav.sharma@shop.com",    "delivered",    29999, "12 MG Road Mumbai",          "BlueDart",    30, 28, 25),
        ("aarav.sharma@shop.com",    "out_for_delivery", 8999, "12 MG Road Mumbai",       "Delhivery",    3,  1, None),
        ("priya.mehta@shop.com",     "delivered",    3499,  "45 Brigade Rd Bangalore",    "DTDC",        20, 18, 15),
        ("priya.mehta@shop.com",     "shipped",      45999, "45 Brigade Rd Bangalore",    "BlueDart",     7,  5, None),
        ("rohan.verma@shop.com",     "processing",   1299,  "7 Park Street Kolkata",      None,           1, None, None),
        ("sneha.patel@shop.com",     "delivered",   134999, "88 Residency Rd Pune",       "FedEx",       45, 43, 40),
        ("sneha.patel@shop.com",     "delivered",    2999,  "88 Residency Rd Pune",       "Delhivery",   15, 13, 10),
        ("karan.gupta@shop.com",     "shipped",      2499,  "22 Anna Salai Chennai",      "DTDC",         5,  3, None),
        ("anjali.nair@shop.com",     "delivered",   129999, "5 Connaught Pl Delhi",       "BlueDart",    60, 58, 55),
        ("anjali.nair@shop.com",     "delivered",    2199,  "5 Connaught Pl Delhi",       "Delhivery",   10,  8,  5),
        ("vikram.singh@shop.com",    "cancelled",    8999,  "34 Linking Rd Mumbai",       None,          12, None, None),
        ("meena.joshi@shop.com",     "delivered",    699,   "18 FC Road Pune",            "India Post",  25, 23, 20),
        ("arjun.das@shop.com",       "out_for_delivery",2999,"99 Jubilee Hills Hyderabad","BlueDart",    4,  2, None),
        ("kavya.reddy@shop.com",     "processing",   8499,  "12 Koramangala Bangalore",   None,          1, None, None),
        ("serial.returner@shop.com", "delivered",    3499,  "Unknown Address Delhi",      "DTDC",        35, 33, 30),
        ("serial.returner@shop.com", "delivered",    8999,  "Unknown Address Delhi",      "Delhivery",   50, 48, 45),
        ("fraud.customer@shop.com",  "delivered",   29999,  "Fake Street 1 Mumbai",       "BlueDart",    20, 18, 15),
    ]
    order_ids = {}
    for i, o in enumerate(orders_raw):
        email, status, total, addr, carrier, d_ago, s_ago, del_ago = o
        tracking = make_tracking() if carrier else None
        shipped_at  = (datetime.now() - timedelta(days=s_ago))   if s_ago   else None
        delivered_at= (datetime.now() - timedelta(days=del_ago)) if del_ago else None
        cur.execute(
            """INSERT INTO orders(customer_email,status,total_amount,shipping_address,tracking_number,carrier,created_at,shipped_at,delivered_at)
               VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (email, status, total, addr, tracking, carrier,
             datetime.now()-timedelta(days=d_ago), shipped_at, delivered_at)
        )
        oid = cur.fetchone()[0]
        order_ids[i] = oid
        if email not in order_ids:
            order_ids[email] = oid

    # ── Order Items ───────────────────────────────────────────────────
    order_items = [
        (order_ids[0],  prod_ids["SONY-WH5-BLK"],  1, 29999),
        (order_ids[1],  prod_ids["NIKE-AM270-10"],  1,  8999),
        (order_ids[2],  prod_ids["LEVIS-511-32"],   1,  3499),
        (order_ids[3],  prod_ids["LEN-IP3-15"],     1, 45999),
        (order_ids[4],  prod_ids["PRES-KETTLE2"],   1,  1299),
        (order_ids[5],  prod_ids["APPLE-IP15P"],    1,134999),
        (order_ids[6],  prod_ids["WILD-BP45-GRN"],  1,  2999),
        (order_ids[7],  prod_ids["FAST-W-ANA21"],   1,  2499),
        (order_ids[8],  prod_ids["SAM-TV65-4K"],    1,129999),
        (order_ids[9],  prod_ids["BOSCH-HB-450"],   1,  2199),
        (order_ids[10], prod_ids["NIKE-AM270-10"],  1,  8999),
        (order_ids[11], prod_ids["NESTLE-KK-24"],   1,   699),
        (order_ids[12], prod_ids["WILD-BP45-GRN"],  1,  2999),
        (order_ids[13], prod_ids["JBL-FLIP7-BLK"],  1,  8499),
        (order_ids[14], prod_ids["LEVIS-511-32"],   1,  3499),
        (order_ids[15], prod_ids["NIKE-AM270-10"],  1,  8999),
        (order_ids[16], prod_ids["SONY-WH5-BLK"],   1, 29999),
    ]
    cur.executemany(
        "INSERT INTO order_items(order_id,product_id,quantity,unit_price,subtotal) VALUES(%s,%s,%s,%s,%s)",
        [(oi[0], oi[1], oi[2], oi[3], oi[2]*oi[3]) for oi in order_items]
    )

    # ── Payments ──────────────────────────────────────────────────────
    payment_data = [
        (order_ids[0],  "aarav.sharma@shop.com",   29999, "credit_card",  "TXN-AA-001",  30),
        (order_ids[1],  "aarav.sharma@shop.com",    8999, "upi",          "TXN-AA-002",   3),
        (order_ids[2],  "priya.mehta@shop.com",     3499, "debit_card",   "TXN-PM-001",  20),
        (order_ids[3],  "priya.mehta@shop.com",    45999, "net_banking",  "TXN-PM-002",   7),
        (order_ids[5],  "sneha.patel@shop.com",   134999, "credit_card",  "TXN-SP-001",  45),
        (order_ids[6],  "sneha.patel@shop.com",     2999, "upi",          "TXN-SP-002",  15),
        # Duplicate charge for fraud demo
        (order_ids[8],  "anjali.nair@shop.com",   129999, "credit_card",  "TXN-AN-001",  60),
        (order_ids[8],  "anjali.nair@shop.com",   129999, "credit_card",  "TXN-AN-DUP",  60),  # duplicate!
        (order_ids[9],  "anjali.nair@shop.com",     2199, "upi",          "TXN-AN-002",  10),
        (order_ids[16], "fraud.customer@shop.com", 29999, "credit_card",  "TXN-FR-001",  20),
    ]
    cur.executemany(
        "INSERT INTO payments(order_id,customer_email,amount,method,status,transaction_id,payment_date) VALUES(%s,%s,%s,%s,%s,%s,%s)",
        [(p[0],p[1],p[2],p[3],"completed",p[4],datetime.now()-timedelta(days=p[5])) for p in payment_data]
    )

    # ── Returns ───────────────────────────────────────────────────────
    returns_data = [
        (order_ids[0],  "aarav.sharma@shop.com",   prod_ids["SONY-WH5-BLK"], "Defective — noise cancelling not working", "approved",  False, None),
        (order_ids[2],  "priya.mehta@shop.com",    prod_ids["LEVIS-511-32"],  "Wrong size delivered",                     "approved",  False, None),
        (order_ids[14], "serial.returner@shop.com",prod_ids["LEVIS-511-32"],  "Changed mind",                             "rejected",  True,  "8 returns in 90 days — serial return pattern flagged"),
        (order_ids[15], "serial.returner@shop.com",prod_ids["NIKE-AM270-10"], "Doesn't fit",                              "flagged",   True,  "Return fraud: excessive return rate"),
        (order_ids[16], "fraud.customer@shop.com", prod_ids["SONY-WH5-BLK"],  "Never received",                          "flagged",   True,  "Empty box fraud suspected — item weight mismatch"),
    ]
    return_ids = {}
    for i, r in enumerate(returns_data):
        resolved = datetime.now() - timedelta(days=5) if r[5] in ("approved","rejected") else None
        cur.execute(
            """INSERT INTO returns(order_id,customer_email,product_id,reason,status,fraud_flag,fraud_reason,resolved_at)
               VALUES(%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (r[0],r[1],r[2],r[3],r[4],r[5],r[6],resolved)
        )
        return_ids[i] = cur.fetchone()[0]

    # ── Refunds ───────────────────────────────────────────────────────
    cur.execute(
        "INSERT INTO refunds(return_id,customer_email,amount,method,status,processed_at) VALUES(%s,%s,%s,%s,%s,%s)",
        (return_ids[0], "aarav.sharma@shop.com", 29999, "original_payment", "completed", datetime.now()-timedelta(days=3))
    )
    cur.execute(
        "INSERT INTO refunds(return_id,customer_email,amount,method,status,processed_at) VALUES(%s,%s,%s,%s,%s,%s)",
        (return_ids[1], "priya.mehta@shop.com",   3499, "store_credit",     "completed", datetime.now()-timedelta(days=2))
    )

    # ── Complaints ────────────────────────────────────────────────────
    complaints_data = [
        ("aarav.sharma@shop.com",   order_ids[0],  "product_defect",  "Headphones stopped working after 2 days. Noise cancelling completely broken.", "resolved", "high",   False, "Replacement dispatched + refund offered"),
        ("anjali.nair@shop.com",    order_ids[8],  "billing_issue",   "I was charged twice for my TV order. Both transactions of ₹1,29,999 appeared.", "open",     "urgent", True,  None),
        ("vikram.singh@shop.com",   order_ids[10], "wrong_item",      "Received black shoes but ordered white. Box was different too.",               "open",     "medium", False, None),
        ("meena.joshi@shop.com",    order_ids[11], "late_delivery",   "Order placed 25 days ago still hasn't arrived per tracking.",                  "resolved", "low",    False, "Delivered — courier delay apologised"),
        ("kavya.reddy@shop.com",    order_ids[13], "out_of_stock",    "Placed and paid for JBL speaker that shows out of stock now.",                 "open",     "high",   False, None),
        ("serial.returner@shop.com",order_ids[14], "return_rejected", "My return was rejected without explanation. This is unacceptable.",            "open",     "medium", False, None),
    ]
    for c in complaints_data:
        resolved_at = datetime.now()-timedelta(days=2) if c[4]=="resolved" else None
        cur.execute(
            """INSERT INTO complaints(customer_email,order_id,type,description,status,priority,escalated,resolution,created_at,resolved_at)
               VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7],
             datetime.now()-timedelta(days=5),resolved_at)
        )

    # ── Reviews ───────────────────────────────────────────────────────
    reviews_data = [
        ("aarav.sharma@shop.com",  prod_ids["SONY-WH5-BLK"], order_ids[0],  5, "Amazing headphones! Worth every penny. Battery life is incredible."),
        ("priya.mehta@shop.com",   prod_ids["LEVIS-511-32"],  order_ids[2],  4, "Good quality jeans, fit well. Slight colour variation from website photo."),
        ("sneha.patel@shop.com",   prod_ids["APPLE-IP15P"],   order_ids[5],  5, "Best phone I've owned. Camera is exceptional. Very happy with purchase."),
        ("anjali.nair@shop.com",   prod_ids["SAM-TV65-4K"],   order_ids[8],  3, "Great picture quality but setup was complicated. Also had billing issue."),
        ("meena.joshi@shop.com",   prod_ids["NESTLE-KK-24"],  order_ids[11], 5, "Perfect gift box. Packaging was great and delivery (eventually) was fine."),
        ("arjun.das@shop.com",     prod_ids["WILD-BP45-GRN"], order_ids[12], 4, "Solid backpack for trekking. Straps are comfortable. Good value for money."),
        ("kavya.reddy@shop.com",   prod_ids["JBL-FLIP7-BLK"], order_ids[13], 1, "Charged me for an out-of-stock item. Very disappointed with this experience."),
    ]
    cur.executemany(
        "INSERT INTO reviews(customer_email,product_id,order_id,rating,comment) VALUES(%s,%s,%s,%s,%s)",
        reviews_data
    )

    # ── Loyalty History ───────────────────────────────────────────────
    loyalty_history = [
        ("aarav.sharma@shop.com",   300, "Purchase order #1 — Sony Headphones",    300),
        ("aarav.sharma@shop.com",   100, "Purchase order #2 — Nike Shoes",         400),
        ("aarav.sharma@shop.com",  3750, "Gold tier bonus points",               4250),
        ("priya.mehta@shop.com",    100, "Purchase order #3 — Levis Jeans",        100),
        ("priya.mehta@shop.com",   1750, "Silver tier welcome bonus",            1850),
        ("sneha.patel@shop.com",   1350, "Purchase — iPhone 15 Pro",             1350),
        ("sneha.patel@shop.com",    100, "Purchase — Wildcraft Backpack",         1450),
        ("sneha.patel@shop.com",   4650, "Gold tier status bonus",               6100),
        ("anjali.nair@shop.com",   1300, "Purchase — Samsung TV",                1300),
        ("anjali.nair@shop.com",   8500, "Platinum tier welcome bonus",          9800),
        ("meena.joshi@shop.com",    100, "Purchase — KitKat Gift Box",             100),
        ("meena.joshi@shop.com",   3100, "Silver tier bonus",                    3200),
        ("arjun.das@shop.com",      100, "Purchase — Wildcraft Backpack",          100),
        ("arjun.das@shop.com",     5400, "Gold tier status upgrade bonus",       5500),
        ("karan.gupta@shop.com",   2400, "Silver tier welcome bonus",            2400),
    ]
    cur.executemany(
        "INSERT INTO loyalty_history(customer_email,points_change,reason,balance_after) VALUES(%s,%s,%s,%s)",
        loyalty_history
    )

    conn.commit()
    print("[OK] Seed data inserted:")
    print(f"   → {len(customers)} customers, {len(products)} products")
    print(f"   → {len(orders_raw)} orders, {len(payment_data)} payments")
    print(f"   → {len(returns_data)} returns, {len(complaints_data)} complaints")
    print(f"   → {len(reviews_data)} reviews, {len(loyalty_history)} loyalty events")


if __name__ == "__main__":
    init_db()