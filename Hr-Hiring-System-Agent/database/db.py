"""
database/db.py
══════════════
PostgreSQL schema + seed data for the HR Hiring Multi-Agent System.

Tables (11):
  users              — role-based login accounts (RBAC)
  jobs               — job postings lifecycle
  candidates         — candidate registry and pipeline state
  screening_notes    — internal recruiter notes
  interviews         — interview slots and metadata
  interview_feedback — post-interview evaluations
  offers             — offer letters and approval chain
  onboarding         — onboarding records
  onboarding_tasks   — individual checklist items
  communications     — full email communication log
  audit_log          — every agent action logged for compliance
"""

import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    connect_timeout = int(os.getenv("DB_CONNECT_TIMEOUT_SEC", 5))
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 5432)),
        dbname=os.getenv("DB_NAME", "hr_hiring"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres"),
        connect_timeout=connect_timeout,
    )


def _ensure_db():
    """Create the database if it does not exist."""
    try:
        conn = get_connection()
        conn.close()
    except psycopg2.OperationalError:
        connect_timeout = int(os.getenv("DB_CONNECT_TIMEOUT_SEC", 5))
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", 5432)),
            dbname="postgres",
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "postgres"),
            connect_timeout=connect_timeout,
        )
        conn.autocommit = True
        conn.cursor().execute(f"CREATE DATABASE {os.getenv('DB_NAME','hr_hiring')}")
        conn.close()


def init_db():
    """Create all tables and seed data. Safe to call multiple times."""
    _ensure_db()
    conn = get_connection()
    cur  = conn.cursor()

    # ── Tables ────────────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        name          VARCHAR(120) NOT NULL,
        email         VARCHAR(120) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role          VARCHAR(30)  NOT NULL CHECK (role IN ('admin','hr_manager','recruiter','hiring_manager')),
        department    VARCHAR(80),
        is_active     BOOLEAN DEFAULT TRUE,
        created_at    TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS jobs (
        id               SERIAL PRIMARY KEY,
        title            VARCHAR(150) NOT NULL,
        department       VARCHAR(80),
        description      TEXT,
        required_skills  TEXT,
        experience_years INTEGER DEFAULT 0,
        salary_min       NUMERIC(12,2),
        salary_max       NUMERIC(12,2),
        location         VARCHAR(100),
        job_type         VARCHAR(30) DEFAULT 'full_time',
        status           VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open','closed','on_hold','draft')),
        deadline         DATE,
        created_by       VARCHAR(120),
        created_at       TIMESTAMP DEFAULT NOW(),
        updated_at       TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS candidates (
        id             SERIAL PRIMARY KEY,
        name           VARCHAR(120) NOT NULL,
        email          VARCHAR(120) NOT NULL,
        job_id         INTEGER REFERENCES jobs(id),
        resume_text    TEXT,
        score          NUMERIC(5,2) DEFAULT 0,
        status         VARCHAR(30)  DEFAULT 'applied'
                         CHECK (status IN ('applied','screening','shortlisted','interview','offer','hired','rejected')),
        source         VARCHAR(60)  DEFAULT 'direct',
        experience_years INTEGER DEFAULT 0,
        "current_role" VARCHAR(100),
        skills         TEXT,
        education      VARCHAR(100),
        shortlisted    BOOLEAN DEFAULT FALSE,
        created_at     TIMESTAMP DEFAULT NOW(),
        updated_at     TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS screening_notes (
        id           SERIAL PRIMARY KEY,
        candidate_id INTEGER REFERENCES candidates(id),
        note         TEXT,
        created_by   VARCHAR(120),
        created_at   TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS interviews (
        id               SERIAL PRIMARY KEY,
        candidate_id     INTEGER REFERENCES candidates(id),
        job_id           INTEGER REFERENCES jobs(id),
        interviewer_email VARCHAR(120),
        interviewer_name  VARCHAR(120),
        scheduled_at     TIMESTAMP,
        duration_mins    INTEGER DEFAULT 60,
        type             VARCHAR(30) DEFAULT 'technical'
                           CHECK (type IN ('technical','hr','culture_fit','final','panel')),
        round            INTEGER DEFAULT 1,
        status           VARCHAR(20) DEFAULT 'scheduled'
                           CHECK (status IN ('scheduled','completed','cancelled','rescheduled','no_show')),
        meeting_link     VARCHAR(255),
        notes            TEXT,
        created_at       TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS interview_feedback (
        id              SERIAL PRIMARY KEY,
        interview_id    INTEGER REFERENCES interviews(id),
        candidate_id    INTEGER REFERENCES candidates(id),
        rating          INTEGER CHECK (rating BETWEEN 1 AND 5),
        technical_score INTEGER CHECK (technical_score BETWEEN 1 AND 10),
        culture_fit     INTEGER CHECK (culture_fit BETWEEN 1 AND 10),
        communication   INTEGER CHECK (communication BETWEEN 1 AND 10),
        notes           TEXT,
        recommendation  VARCHAR(20) CHECK (recommendation IN ('strong_yes','yes','maybe','no','strong_no')),
        submitted_by    VARCHAR(120),
        created_at      TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS offers (
        id             SERIAL PRIMARY KEY,
        candidate_id   INTEGER REFERENCES candidates(id),
        job_id         INTEGER REFERENCES jobs(id),
        salary         NUMERIC(12,2),
        currency       VARCHAR(10) DEFAULT 'INR',
        start_date     DATE,
        benefits       TEXT,
        equity         VARCHAR(80),
        status         VARCHAR(30) DEFAULT 'draft'
                         CHECK (status IN ('draft','pending_approval','approved','sent','accepted','declined','expired')),
        approved_by    VARCHAR(120),
        approved_at    TIMESTAMP,
        sent_at        TIMESTAMP,
        response_at    TIMESTAMP,
        decline_reason TEXT,
        created_by     VARCHAR(120),
        created_at     TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS onboarding (
        id              SERIAL PRIMARY KEY,
        candidate_id    INTEGER REFERENCES candidates(id),
        job_id          INTEGER REFERENCES jobs(id),
        start_date      DATE,
        buddy_email     VARCHAR(120),
        buddy_name      VARCHAR(120),
        completion_pct  NUMERIC(5,2) DEFAULT 0,
        status          VARCHAR(20) DEFAULT 'pending'
                          CHECK (status IN ('pending','in_progress','completed')),
        welcome_sent    BOOLEAN DEFAULT FALSE,
        created_at      TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS onboarding_tasks (
        id            SERIAL PRIMARY KEY,
        onboarding_id INTEGER REFERENCES onboarding(id),
        task_name     VARCHAR(200),
        category      VARCHAR(50) CHECK (category IN ('it_setup','documentation','training','access','orientation','other')),
        assigned_to   VARCHAR(120),
        due_date      DATE,
        completed     BOOLEAN DEFAULT FALSE,
        completed_at  TIMESTAMP,
        notes         TEXT
    );

    CREATE TABLE IF NOT EXISTS communications (
        id           SERIAL PRIMARY KEY,
        candidate_id INTEGER REFERENCES candidates(id),
        type         VARCHAR(50),
        subject      VARCHAR(255),
        body_preview TEXT,
        sent_at      TIMESTAMP DEFAULT NOW(),
        sent_by      VARCHAR(120),
        status       VARCHAR(20) DEFAULT 'sent'
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id          SERIAL PRIMARY KEY,
        user_email  VARCHAR(120),
        role        VARCHAR(30),
        action      VARCHAR(100),
        entity_type VARCHAR(50),
        entity_id   INTEGER,
        details     TEXT,
        created_at  TIMESTAMP DEFAULT NOW()
    );
    """)
    conn.commit()

    # ── Seed data — only if tables are empty ──────────────────────────
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] > 0:
        conn.close()
        return

    # Bcrypt hashes (pre-computed for speed — never compute in prod without proper bcrypt)
    # These are bcrypt hashes of: admin123, hr123, rec123, hm123
    import hashlib
    def simple_hash(pw: str) -> str:
        """Simple deterministic hash for demo — use bcrypt in production."""
        return hashlib.sha256((pw + "hr_salt_2026").encode()).hexdigest()

    cur.execute("""
    INSERT INTO users (name, email, password_hash, role, department) VALUES
      ('System Admin',        'admin@hrapp.com',          %s, 'admin',          'IT Administration'),
      ('Priya Sharma',        'hr.manager@hrapp.com',     %s, 'hr_manager',     'Human Resources'),
      ('Rahul Verma',         'recruiter@hrapp.com',      %s, 'recruiter',      'Talent Acquisition'),
      ('Anjali Singh',        'hiring.manager@hrapp.com', %s, 'hiring_manager', 'Engineering'),
      ('Vikram Nair',         'v.nair@hrapp.com',         %s, 'recruiter',      'Talent Acquisition'),
      ('Sneha Patel',         's.patel@hrapp.com',        %s, 'hr_manager',     'Human Resources')
    """, (
        simple_hash("admin123"),
        simple_hash("hr123"),
        simple_hash("rec123"),
        simple_hash("hm123"),
        simple_hash("rec456"),
        simple_hash("hr456"),
    ))

    cur.execute("""
    INSERT INTO jobs (title, department, description, required_skills, experience_years,
                      salary_min, salary_max, location, job_type, status, deadline, created_by) VALUES
      ('Senior Backend Engineer',   'Engineering',       'Build scalable APIs and microservices for our core platform.',
       'Python, FastAPI, PostgreSQL, Redis, Docker, Kubernetes', 4, 1800000, 2800000, 'Bengaluru', 'full_time', 'open', '2026-03-31', 'hr.manager@hrapp.com'),

      ('Product Manager',           'Product',           'Own product roadmap and coordinate cross-functional teams.',
       'Product strategy, Roadmapping, SQL, Agile, Stakeholder management', 5, 2000000, 3200000, 'Mumbai', 'full_time', 'open', '2026-03-15', 'hr.manager@hrapp.com'),

      ('Data Scientist',            'Analytics',         'Build ML models and data pipelines for business insights.',
       'Python, scikit-learn, TensorFlow, SQL, Spark, Statistics', 3, 1600000, 2400000, 'Bengaluru', 'full_time', 'open', '2026-04-15', 'hr.manager@hrapp.com'),

      ('DevOps Engineer',           'Engineering',       'Manage CI/CD pipelines, cloud infrastructure, and reliability.',
       'AWS, Terraform, Kubernetes, Docker, Jenkins, Linux', 3, 1400000, 2200000, 'Remote', 'full_time', 'open', '2026-03-20', 'hr.manager@hrapp.com'),

      ('UI/UX Designer',            'Design',            'Design beautiful and intuitive user experiences for web and mobile.',
       'Figma, User Research, Prototyping, CSS, Design Systems', 2, 1000000, 1600000, 'Pune', 'full_time', 'open', '2026-03-25', 'hr.manager@hrapp.com'),

      ('Frontend Engineer',         'Engineering',       'Build React-based frontends with great performance.',
       'React, TypeScript, CSS, Testing, REST APIs', 3, 1200000, 2000000, 'Bengaluru', 'full_time', 'on_hold', '2026-04-01', 'recruiter@hrapp.com'),

      ('Marketing Manager',         'Marketing',         'Lead digital marketing campaigns and brand strategy.',
       'Digital marketing, SEO, Analytics, Content strategy, Budget management', 4, 1400000, 2200000, 'Mumbai', 'full_time', 'closed', '2026-02-28', 'hr.manager@hrapp.com')
    """)

    cur.execute("""
    INSERT INTO candidates (name, email, job_id, resume_text, score, status, source,
                            experience_years, "current_role", skills, education, shortlisted) VALUES
      -- Job 1: Senior Backend Engineer
      ('Arjun Mehta',    'arjun.mehta@email.com',    1, 'Senior Python developer at Flipkart. 5 years building microservices.',
       88, 'shortlisted', 'LinkedIn', 5, 'Senior Software Engineer', 'Python, FastAPI, PostgreSQL, Docker, Kubernetes', 'B.Tech CSE IIT Bombay', TRUE),

      ('Divya Krishnan', 'divya.k@email.com',        1, 'Backend engineer at Swiggy. PostgreSQL expert.',
       82, 'interview',   'Naukri',   4, 'Backend Engineer',         'Python, Django, PostgreSQL, Redis, AWS',          'B.Tech CSE BITS Pilani', TRUE),

      ('Rohit Jain',     'rohit.jain@email.com',     1, 'Full stack developer, strong Python backend.',
       71, 'screening',   'direct',   3, 'Software Developer',       'Python, Flask, MySQL, Docker',                    'B.Tech CSE VIT', FALSE),

      ('Neha Gupta',     'neha.gupta@email.com',     1, 'Backend developer at startup.',
       55, 'applied',     'Indeed',   2, 'Junior Backend Dev',       'Python, Node.js, MongoDB',                        'B.Tech IT Pune', FALSE),

      ('Karan Shah',     'karan.shah@email.com',     1, 'DevOps-leaning backend engineer.',
       48, 'rejected',    'Referral', 1, 'Junior Developer',         'Python, Bash, Linux',                             'B.Tech ECE', FALSE),

      -- Job 2: Product Manager
      ('Riya Desai',     'riya.desai@email.com',     2, 'PM at Razorpay for 5 years. Led 3 major product launches.',
       91, 'offer',       'LinkedIn', 5, 'Senior Product Manager',   'Product strategy, SQL, Agile, Analytics',        'MBA IIM Ahmedabad', TRUE),

      ('Amit Bose',      'amit.bose@email.com',      2, 'Associate PM at MakeMyTrip.',
       76, 'interview',   'AngelList', 3, 'Associate PM',            'Roadmapping, Jira, SQL, User research',           'MBA ISB Hyderabad', TRUE),

      ('Preet Kaur',     'preet.kaur@email.com',     2, 'Business analyst wanting to transition to PM.',
       62, 'screening',   'direct',   3, 'Business Analyst',         'SQL, Excel, Stakeholder management',              'MBA Symbiosis', FALSE),

      -- Job 3: Data Scientist
      ('Siddharth Rao',  'sid.rao@email.com',        3, 'Data scientist at Amazon. Built recommendation systems.',
       89, 'interview',   'LinkedIn', 4, 'Data Scientist II',        'Python, TensorFlow, SQL, Spark, Statistics',      'M.Tech Data Science IIT Delhi', TRUE),

      ('Meera Nambiar',  'meera.n@email.com',        3, 'ML engineer at healthcare startup.',
       83, 'shortlisted', 'Naukri',   3, 'ML Engineer',              'Python, scikit-learn, SQL, Tableau',              'B.Tech + M.Tech NIT', TRUE),

      ('Farhan Khan',    'farhan.k@email.com',       3, 'Fresher with strong ML projects.',
       58, 'applied',     'campus',   1, 'Intern',                   'Python, scikit-learn, Pandas',                    'M.Tech AI IIT Hyderabad', FALSE),

      -- Job 4: DevOps Engineer
      ('Tanvi Joshi',    'tanvi.j@email.com',        4, 'DevOps at Infosys. AWS certified.',
       85, 'interview',   'LinkedIn', 4, 'DevOps Engineer',          'AWS, Terraform, Kubernetes, Docker, Jenkins',     'B.Tech CSE BITS Goa', TRUE),

      ('Suresh Kumar',   'suresh.k@email.com',       4, 'Sysadmin transitioning to DevOps.',
       66, 'screening',   'Naukri',   5, 'Systems Administrator',    'Linux, Bash, AWS basics, Docker',                 'B.Tech ECE', FALSE),

      -- Job 5: UI/UX Designer
      ('Aisha Kapoor',   'aisha.k@email.com',        5, 'Product designer at Zomato. Figma expert.',
       87, 'shortlisted', 'Behance',  3, 'Product Designer',         'Figma, User Research, Prototyping, CSS',          'B.Des NID Ahmedabad', TRUE),

      ('Dev Malhotra',   'dev.m@email.com',          5, 'Freelance UX designer with startup experience.',
       73, 'screening',   'direct',   2, 'Freelance Designer',       'Figma, Sketch, User testing',                     'B.Des NIFT', FALSE)
    """)

    # Interviews
    cur.execute("""
    INSERT INTO interviews (candidate_id, job_id, interviewer_email, interviewer_name,
                            scheduled_at, duration_mins, type, round, status, meeting_link) VALUES
      (2, 1, 'hiring.manager@hrapp.com', 'Anjali Singh',  '2026-02-28 10:00:00', 60, 'technical',   1, 'completed',  'https://meet.google.com/abc-defg-hij'),
      (7, 2, 'hiring.manager@hrapp.com', 'Anjali Singh',  '2026-02-27 14:00:00', 45, 'hr',          1, 'completed',  'https://meet.google.com/xyz-pqrs-tuv'),
      (9, 3, 'hiring.manager@hrapp.com', 'Anjali Singh',  '2026-03-05 11:00:00', 60, 'technical',   1, 'scheduled',  'https://meet.google.com/ds1-abc-111'),
      (12,4, 'hiring.manager@hrapp.com', 'Anjali Singh',  '2026-03-06 15:00:00', 60, 'technical',   1, 'scheduled',  'https://meet.google.com/dev-xyz-222'),
      (1, 1, 'v.nair@hrapp.com',         'Vikram Nair',   '2026-02-25 10:00:00', 90, 'final',       2, 'completed',  'https://meet.google.com/fin-abc-999')
    """)

    # Interview feedback
    cur.execute("""
    INSERT INTO interview_feedback (interview_id, candidate_id, rating, technical_score,
                                    culture_fit, communication, notes, recommendation, submitted_by) VALUES
      (1, 2, 4, 8, 7, 8, 'Strong PostgreSQL skills. Good system design. Needs improvement on Kubernetes.', 'yes', 'hiring.manager@hrapp.com'),
      (2, 7, 3, 5, 8, 7, 'Good product sense. SQL skills need more depth. Promising candidate.', 'maybe', 'hiring.manager@hrapp.com'),
      (5, 1, 5, 10, 9, 9, 'Exceptional. Best candidate we have seen this quarter. Strong offer recommended.', 'strong_yes', 'v.nair@hrapp.com')
    """)

    # Offers
    cur.execute("""
    INSERT INTO offers (candidate_id, job_id, salary, currency, start_date, benefits,
                        equity, status, approved_by, sent_at, created_by) VALUES
      (6, 2, 2800000, 'INR', '2026-03-15', 'Health insurance (family), 30 days PTO, Home office allowance ₹50k, ESOPs',
       '0.1% equity, 4-year vesting', 'sent', 'hr.manager@hrapp.com', '2026-02-20 09:00:00', 'hr.manager@hrapp.com')
    """)

    # Onboarding
    cur.execute("""
    INSERT INTO onboarding (candidate_id, job_id, start_date, buddy_email, buddy_name,
                             completion_pct, status, welcome_sent) VALUES
      (6, 2, '2026-03-15', 'amit.lead@hrapp.com', 'Amit Lead', 20, 'pending', FALSE)
    """)

    cur.execute("""
    INSERT INTO onboarding_tasks (onboarding_id, task_name, category, assigned_to, due_date) VALUES
      (1, 'Laptop provisioning and setup',      'it_setup',      'it@hrapp.com',          '2026-03-14'),
      (1, 'Email and Slack account creation',   'it_setup',      'it@hrapp.com',          '2026-03-14'),
      (1, 'ID card and access badge',           'documentation', 'admin@hrapp.com',        '2026-03-15'),
      (1, 'Sign NDA and employment agreement',  'documentation', 'hr.manager@hrapp.com',   '2026-03-15'),
      (1, 'Product onboarding training',        'training',      'hr.manager@hrapp.com',   '2026-03-20'),
      (1, 'GitHub and Jira access setup',       'access',        'it@hrapp.com',           '2026-03-15'),
      (1, 'Team orientation meeting',           'orientation',   'hiring.manager@hrapp.com','2026-03-16')
    """)

    # Communications log
    cur.execute("""
    INSERT INTO communications (candidate_id, type, subject, body_preview, sent_by) VALUES
      (1, 'application_confirmation', 'Application Received – Senior Backend Engineer', 'Thank you for applying...', 'system'),
      (2, 'interview_invitation',     'Interview Scheduled – Technical Round 1',        'We would like to invite you...', 'recruiter@hrapp.com'),
      (5, 'rejection',                'Application Update – Senior Backend Engineer',   'Thank you for your interest...', 'recruiter@hrapp.com'),
      (6, 'offer',                    'Offer Letter – Product Manager at HireSmart',    'We are pleased to extend...', 'hr.manager@hrapp.com'),
      (7, 'interview_invitation',     'Interview Scheduled – HR Round',                 'We would like to invite you...', 'recruiter@hrapp.com')
    """)

    conn.commit()
    conn.close()
    print("[OK]  HR Hiring DB initialised with seed data.")
