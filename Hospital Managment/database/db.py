"""
database/db.py — Full hospital multi-agent system DB
Tables: patients, doctors, appointments, invoices, inventory_items,
        reorder_alerts, prescriptions, lab_tests, beds, ward_events
"""
import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"), port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "hospital_db"), user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )

def create_database_if_not_exists():
    db_name = os.getenv("DB_NAME", "hospital_db")
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"), port=os.getenv("DB_PORT", "5432"),
            dbname="postgres", user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", ""),
        )
        conn.autocommit = True
        cur = conn.cursor()
        
        # Check if database exists
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
        exists = cur.fetchone()
        
        if not exists:
            try:
                cur.execute(f'CREATE DATABASE "{db_name}"')
                print(f"[DB] Database '{db_name}' created.")
            except psycopg2.errors.DuplicateDatabase:
                print(f"[DB] Database '{db_name}' already exists (race condition handled).")
        else:
            print(f"[DB] Database '{db_name}' already exists.")
            
        cur.close(); conn.close()
    except Exception as e:
        print(f"[DB] Warning during database check/creation: {e}")

def init_db():
    create_database_if_not_exists()
    conn = get_connection()
    # Use autocommit to handle advisory locks outside a transaction or manage manually
    conn.autocommit = True
    cur = conn.cursor()

    # Acquire an advisory lock (id 12345) to ensure only one process initializes at a time
    print("[DB] Attempting to acquire initialization lock...")
    cur.execute("SELECT pg_advisory_lock(12345)")
    try:
        print("[DB] Initialization lock acquired. Running setup...")

        cur.execute("""CREATE TABLE IF NOT EXISTS patients (
            id SERIAL PRIMARY KEY, name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE, age INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT NOW())""")

        cur.execute("""CREATE TABLE IF NOT EXISTS doctors (
            id SERIAL PRIMARY KEY, name TEXT NOT NULL,
            specialization TEXT NOT NULL, email TEXT NOT NULL UNIQUE)""")

        cur.execute("""CREATE TABLE IF NOT EXISTS appointments (
            id SERIAL PRIMARY KEY, patient_email TEXT NOT NULL,
            doctor_id INTEGER NOT NULL REFERENCES doctors(id),
            appointment_date DATE NOT NULL, appointment_time TIME NOT NULL,
            reason TEXT, status TEXT DEFAULT 'scheduled',
            created_at TIMESTAMP DEFAULT NOW())""")

        # Backfill cleanup for historical duplicates created before slot constraints existed.
        # Keep the earliest scheduled row and cancel later duplicates per doctor slot.
        cur.execute("""
            WITH ranked AS (
                SELECT id,
                       ROW_NUMBER() OVER (
                           PARTITION BY doctor_id, appointment_date, appointment_time
                           ORDER BY created_at, id
                       ) AS rn
                FROM appointments
                WHERE status='scheduled'
            )
            UPDATE appointments a
            SET status='cancelled',
                reason=CASE
                    WHEN COALESCE(a.reason, '') = '' THEN '[auto-cancelled duplicate doctor slot]'
                    ELSE a.reason || ' [auto-cancelled duplicate doctor slot]'
                END
            FROM ranked r
            WHERE a.id = r.id AND r.rn > 1
        """)

        # Prevent a patient from holding two appointments at the same date+time.
        cur.execute("""
            WITH ranked AS (
                SELECT id,
                       ROW_NUMBER() OVER (
                           PARTITION BY patient_email, appointment_date, appointment_time
                           ORDER BY created_at, id
                       ) AS rn
                FROM appointments
                WHERE status='scheduled'
            )
            UPDATE appointments a
            SET status='cancelled',
                reason=CASE
                    WHEN COALESCE(a.reason, '') = '' THEN '[auto-cancelled duplicate patient slot]'
                    ELSE a.reason || ' [auto-cancelled duplicate patient slot]'
                END
            FROM ranked r
            WHERE a.id = r.id AND r.rn > 1
        """)

        # Enforce conflict-free scheduling at DB level to close race-condition windows.
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_appointments_doctor_slot_scheduled
            ON appointments (doctor_id, appointment_date, appointment_time)
            WHERE status='scheduled'
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_appointments_patient_slot_scheduled
            ON appointments (patient_email, appointment_date, appointment_time)
            WHERE status='scheduled'
        """)

        cur.execute("""CREATE TABLE IF NOT EXISTS invoices (
            id SERIAL PRIMARY KEY, patient_email TEXT NOT NULL,
            appointment_id INTEGER REFERENCES appointments(id),
            items JSONB DEFAULT '[]', subtotal NUMERIC(10,2) DEFAULT 0,
            insurance_covered NUMERIC(10,2) DEFAULT 0,
            total_due NUMERIC(10,2) DEFAULT 0,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW())""")

        cur.execute("""CREATE TABLE IF NOT EXISTS inventory_items (
            id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL, quantity INTEGER DEFAULT 0,
            unit TEXT DEFAULT 'units', reorder_level INTEGER DEFAULT 50,
            expiry_date DATE, supplier TEXT, cost_per_unit NUMERIC(10,2) DEFAULT 0)""")

        cur.execute("""CREATE TABLE IF NOT EXISTS reorder_alerts (
            id SERIAL PRIMARY KEY, item_id INTEGER REFERENCES inventory_items(id),
            quantity_at_trigger INTEGER, status TEXT DEFAULT 'open',
            triggered_at TIMESTAMP DEFAULT NOW(), resolved_at TIMESTAMP)""")

        cur.execute("""CREATE TABLE IF NOT EXISTS prescriptions (
            id SERIAL PRIMARY KEY, patient_email TEXT NOT NULL,
            doctor_id INTEGER REFERENCES doctors(id),
            medication TEXT NOT NULL, dosage TEXT NOT NULL,
            frequency TEXT NOT NULL, duration_days INTEGER,
            status TEXT DEFAULT 'active', notes TEXT,
            created_at TIMESTAMP DEFAULT NOW())""")

        cur.execute("""CREATE TABLE IF NOT EXISTS lab_tests (
            id SERIAL PRIMARY KEY, patient_email TEXT NOT NULL,
            doctor_id INTEGER REFERENCES doctors(id),
            test_name TEXT NOT NULL, ordered_at TIMESTAMP DEFAULT NOW(),
            status TEXT DEFAULT 'pending', result TEXT,
            critical_flag BOOLEAN DEFAULT FALSE, notified_at TIMESTAMP)""")

        cur.execute("""CREATE TABLE IF NOT EXISTS beds (
            id SERIAL PRIMARY KEY, ward_name TEXT NOT NULL,
            bed_number TEXT NOT NULL UNIQUE,
            status TEXT DEFAULT 'available',
            patient_email TEXT, assigned_at TIMESTAMP)""")

        cur.execute("""CREATE TABLE IF NOT EXISTS ward_events (
            id SERIAL PRIMARY KEY, bed_id INTEGER REFERENCES beds(id),
            event_type TEXT NOT NULL, patient_email TEXT,
            performed_at TIMESTAMP DEFAULT NOW(), notes TEXT)""")

        # Seed doctors
        cur.execute("SELECT COUNT(*) FROM doctors")
        if cur.fetchone()[0] == 0:
            cur.executemany("INSERT INTO doctors (name, specialization, email) VALUES (%s,%s,%s)", [
                ("Dr. Aisha Patel", "Cardiologist",     "aisha.patel@hospital.com"),
                ("Dr. John Smith",  "General Physician", "john.smith@hospital.com"),
                ("Dr. Maria Lopez", "Dermatologist",    "maria.lopez@hospital.com"),
                ("Dr. Raj Kumar",   "Neurologist",      "raj.kumar@hospital.com"),
            ])

        # Seed inventory
        cur.execute("SELECT COUNT(*) FROM inventory_items")
        if cur.fetchone()[0] == 0:
            cur.executemany("INSERT INTO inventory_items (name,category,quantity,unit,reorder_level,cost_per_unit) VALUES (%s,%s,%s,%s,%s,%s)", [
                ("Surgical Gloves",   "PPE",      200, "boxes",   50,  12.50),
                ("Surgical Masks",    "PPE",      500, "boxes",   100,  8.00),
                ("Paracetamol 500mg", "Medicine",1000, "tablets", 200,  0.05),
                ("IV Fluid Saline",   "Fluid",    150, "bags",     30,  4.50),
                ("Syringes 5ml",      "Equipment",800, "units",   100,  0.30),
                ("Blood Test Tubes",  "Lab",      300, "units",    50,  0.80),
                ("Bandages",          "Wound",    400, "rolls",    80,  2.00),
                ("Oxygen Cylinders",  "Equipment", 20, "units",     5,120.00),
                ("Hand Sanitizer",    "PPE",      100, "bottles",  20,  5.00),
                ("Disposable Gowns",  "PPE",      250, "units",    60,  3.50),
            ])

        # Seed beds
        cur.execute("SELECT COUNT(*) FROM beds")
        if cur.fetchone()[0] == 0:
            beds = []
            for ward, prefix, count in [("General Ward","GW",10),("ICU","ICU",5),("Cardiology","CW",6),("Neurology","NW",6)]:
                for i in range(1, count + 1):
                    beds.append((ward, f"{prefix}-{i:02d}", "available"))
            cur.executemany("INSERT INTO beds (ward_name,bed_number,status) VALUES (%s,%s,%s)", beds)

    finally:
        cur.execute("SELECT pg_advisory_unlock(12345)")
        print("[DB] Initialization lock released.")
        conn.commit(); cur.close(); conn.close()
    print("[DB] Full hospital database initialized.")
