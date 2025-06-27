import sqlite3
from utils import generate_uuid, generate_password_hash, generate_timestamp

DATABASE = "data.db"

def get_conn_curs():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    curs = conn.cursor()
    curs.execute("PRAGMA foreign_keys = ON")
    return conn, curs

def commit_close(conn, curs):
    conn.commit()
    curs.close()
    conn.close()

def init_db():
    conn, curs = get_conn_curs()
    curs.executescript(""" 
        CREATE TABLE IF NOT EXISTS users(
        uuid TEXT UNIQUE NOT NULL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS policies(
        uuid TEXT UNIQUE NOT NULL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        pdf_link TEXT
        );
        CREATE TABLE IF NOT EXISTS assignments(
        uuid TEXT UNIQUE NOT NULL PRIMARY KEY,
        user TEXT NOT NULL,
        policy TEXT NOT NULL,
        assigned_at INTEGER,
        timeframe_seconds INTEGER,
        completed_at INTEGER,
        FOREIGN KEY (user) REFERENCES users(uuid) ON DELETE CASCADE ON UPDATE CASCADE,
        FOREIGN KEY (policy) REFERENCES policies(uuid) ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE TABLE IF NOT EXISTS tags(
        uuid TEXT UNIQUE NOT NULL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        members TEXT
        );
    """)
    commit_close(conn, curs)

def create_user(email, name, password, is_admin):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = curs.fetchone()
    if user:
        commit_close(conn, curs)
        return {
            "status": "409",
            "message": "User email already exists",
            "data": None
            }
    uuid = generate_uuid()
    password_hash = generate_password_hash(password)
    curs.execute("INSERT INTO users (uuid, email, name, password_hash, is_admin) VALUES (?, ?, ?, ?, ?)", (uuid, email, name, password_hash, is_admin))
    commit_close(conn, curs)
    return {
        "status": "201",
        "message": "User created successfully",
        "data": None
        }
    
def get_user(uuid=None, email=None):
    conn, curs = get_conn_curs()
    if uuid:
        curs.execute("SELECT * FROM users WHERE uuid = ?", (uuid,))
    elif email:
        curs.execute("SELECT * FROM users WHERE email = ?", (email,))
    else:
        commit_close(conn, curs)
        return {
            "status": "400",
            "message": "Insufficient parameters",
            "data": None
            }
    user = curs.fetchone()
    commit_close(conn, curs)
    if not user:
        return {
            "status": "404",
            "message": "User not found",
            "data": None
            }
    return {
        "status": "200",
        "message": "User found successfully",
        "data": dict(user)
        }

def promote_user_to_admin(uuid):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM users WHERE uuid = ?", (uuid,))
    user = curs.fetchone()
    if not user:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "User not found",
            "data": None
            }
    if user["is_admin"] == 1:
        commit_close(conn, curs)
        return {
            "status": "409",
            "message": "User is already administrator",
            "data": None
            }
    curs.execute("UPDATE users SET is_admin = 1 WHERE uuid = ?", (uuid,))
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "User promoted to administrator successfully",
        "data": None
        }
    
def demote_user_from_admin(uuid):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM users WHERE uuid = ?", (uuid,))
    user = curs.fetchone()
    if not user:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "User not found",
            "data": None
            }
    if user["is_admin"] == 0:
        commit_close(conn, curs)
        return {
            "status": "409",
            "message": "User is already not administrator",
            "data": None
            }
    curs.execute("UPDATE users SET is_admin = 0 WHERE uuid = ?", (uuid,))
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "User demoted to simple user successfully",
        "data": None
        }

def create_policy(name, description, pdf_link):
    conn, curs = get_conn_curs()
    curs.execute("SELECT uuid FROM policies WHERE name = ?", (name,))
    if curs.fetchone():
        commit_close(conn, curs)
        return {
            "status": "409",
            "message": "Policy name already exists",
            "data": None
            }
    uuid = generate_uuid()
    curs.execute("INSERT INTO policies (uuid, name, description, pdf_link) VALUES (?, ?, ?, ?)", (uuid, name, description, pdf_link))
    commit_close(conn, curs)
    return {
        "status": "201",
        "message": "Policy created successfully",
        "data": {
            "uuid": uuid,
            "name": name,
            "description": description,
            "pdf_link": pdf_link
            }
        }

def get_policy(uuid=None, name=None):
    conn, curs = get_conn_curs()
    if uuid:
        curs.execute("SELECT * FROM policies WHERE uuid = ?", (uuid,))
    elif name:
        curs.execute("SELECT * FROM policies WHERE name = ?", (name,))
    else:
        commit_close(conn, curs)
        return {
            "status": "400",
            "message": "Insufficient parameters",
            "data": None
            }
    policy = curs.fetchone()
    commit_close(conn, curs)
    if not policy:
        return {
            "status": "404",
            "message": "Policy not found",
            "data": None
            }
    return {
        "status": "200",
        "message": "Policy found successfully",
        "data": dict(policy)
        }

def edit_policy(uuid, name, description, pdf_link):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM policies WHERE uuid = ?", (uuid,))
    policy = curs.fetchone()
    if not policy:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "Policy not found",
            "data": None
            }
    curs.execute("UPDATE policies SET name = ?, description = ?, pdf_link = ? WHERE uuid = ?", (name, description, pdf_link, uuid))
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Policy edited successfully",
        "data": None
        }

def delete_policy(uuid):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM policies WHERE uuid = ?", (uuid,))
    policy = curs.fetchone()
    if not policy:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "Policy not found",
            "data": None
            }
    curs.execute("DELETE FROM policies WHERE uuid = ?", (uuid,))
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Policy deleted successfully",
        "data": None
        }

def create_assignment(user_uuid, policy_uuid, timeframe_days): 
    conn, curs = get_conn_curs()
    curs.execute("SELECT uuid FROM users WHERE uuid = ?", (user_uuid,))
    user = curs.fetchone()
    if not user:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "User not found",
            "data": None
            }
    curs.execute("SELECT uuid FROM policies WHERE uuid = ?", (policy_uuid,))
    policy = curs.fetchone()
    if not policy:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "Policy not found",
            "data": None
            }
    curs.execute("SELECT uuid FROM assignments WHERE user = ? AND policy = ?", (user_uuid, policy_uuid,))
    if curs.fetchone():
        commit_close(conn, curs)
        return {
            "status": "409",
            "message": "Assignment already exists",
            "data": None
            }
    timeframe_seconds = timeframe_days * 24 * 60 * 60
    uuid = generate_uuid()
    assigned_at = generate_timestamp()
    curs.execute("INSERT INTO assignments (uuid, user, policy, assigned_at, timeframe_seconds) VALUES (?, ?, ?, ?, ?)", (uuid, user_uuid, policy_uuid, assigned_at, timeframe_seconds))
    commit_close(conn, curs)
    return {
        "status": "201",
        "message": "Assignment created successfully",
        "data": None
        }

def attest_assignment(uuid):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM assignments WHERE uuid = ?", (uuid,))
    assignment = curs.fetchone()
    if not assignment:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "Assignment not found",
            "data": None
            }
    if assignment["completed_at"]:
        commit_close(conn, curs)
        return {
            "status": "409",
            "message": "Assignment already attested",
            "data": None
            }
    curs.execute("UPDATE assignments SET completed_at = ? WHERE uuid = ?", (generate_timestamp(), uuid))
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Assignment attested successfully",
        "data": None
        }

def get_assignment(uuid=None, user=None, policy=None):
    conn, curs = get_conn_curs()
    if uuid:
        curs.execute("SELECT * FROM assignments WHERE uuid = ?", (uuid,))
    elif user and policy:
        curs.execute("SELECT * FROM assignments WHERE user = ? AND policy = ?", (user, policy,))
    else:
        commit_close(conn, curs)  
        return {
            "status": "400",
            "message": "Insufficient parameters",
            "data": None
            }
    assignment = curs.fetchone()
    commit_close(conn, curs)
    if not assignment:
        return {
            "status": "404",
            "message": "Assignment not found",
            "data": None
            }
    return {
        "status": "200",
        "message": "Assignment found successfully",
        "data": dict(assignment)
        }
        
def delete_assignment(uuid):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM assignments WHERE uuid = ?", (uuid,))
    assignment = curs.fetchone()
    if not assignment:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "Assignment not found",
            "data": None
            }
    curs.execute("DELETE FROM assignments WHERE uuid = ?", (uuid,))
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Assignment deleted successfully",
        "data": None
        }

def create_tag(name, description=None, members=None):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM tags WHERE name = ?", (name,))
    tag = curs.fetchone()
    if tag:
        commit_close(conn, curs)
        return {
            "status": "409",
            "message": "Tag name already exists",
            "data": None
            }
    uuid = generate_uuid()
    curs.execute("INSERT INTO tags (uuid, name, description, members) VALUES (?, ?, ?, ?)", (uuid, name, description, members))
    commit_close(conn, curs)
    return {
        "status": "201",
        "message": "Tag created successfully",
        "data": None
        }

def update_tag_members(uuid, name=None, description=None, members=None):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM tags WHERE uuid = ?", (uuid,))
    tag = curs.fetchone()
    if not tag:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "Tag not found",
            "data": None
            }
    if not name:
        name = tag["name"]
    if not description:
        description = tag["description"]
    if not members:
        members = tag["members"]
    curs.execute("UPDATE tags SET name = ?, description = ?, members = ? WHERE uuid = ?", (name, description, members, uuid))
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Tag updated successfully",
        "data": None
        }

def delete_tag(uuid):
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM tags WHERE uuid = ?", (uuid,))
    tag = curs.fetchone()
    if not tag:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "Tag not found",
            "data": None
            }
    curs.execute("DELETE FROM tags WHERE uuid = ?", (uuid,))
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Tag deleted successfully",
        "data": None
        }

def get_user_pending_assignments(uuid):
    conn, curs = get_conn_curs()
    curs.execute('SELECT * FROM users WHERE uuid = ?', (uuid,))
    user = curs.fetchone()
    if not user:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "User not found",
            "data": None
            }
    curs.execute("""
        SELECT a.*, p.name as policy_name 
        FROM assignments a 
        JOIN policies p ON a.policy = p.uuid 
        WHERE a.user = ? AND a.completed_at IS NULL
    """, (uuid,))
    assignments = curs.fetchall()
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Assignments found successfully",
        "data": assignments
        }

def get_policies():
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM policies")
    policies = curs.fetchall()
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Policies found successfully",
        "data": policies
        }

def get_assignments():
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM assignments")
    assignments = curs.fetchall()
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Assignments found successfully",
        "data": assignments
        }

def get_users():
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM users")
    users = curs.fetchall()
    commit_close(conn, curs)
    return {
        "status": "200",
        "message": "Users found successfully",
        "data": users
        }

def get_pending_assignments():
    conn, curs = get_conn_curs()
    
    # Get all pending assignments with user name and policy name
    curs.execute("""
        SELECT a.*, u.name as user_name, p.name as policy_name 
        FROM assignments a 
        JOIN users u ON a.user = u.uuid 
        JOIN policies p ON a.policy = p.uuid 
        WHERE a.completed_at IS NULL
    """)
    
    assignments = curs.fetchall()
    commit_close(conn, curs)
    
    return {
        "status": "200",
        "message": "Pending assignments found successfully",
        "data": assignments
    }

def seed_db():
    create_user('admin@admin.com', 'Admin', 'admin', 1)
    create_user('user@user.com', 'User', 'user', 0)
    create_policy('Policy 1', 'Description 1', 'https://example.com/policy1.pdf')
    create_policy('Policy 2', 'Description 2', 'https://example.com/policy2.pdf')
    create_policy('Policy 3', 'Description 3', 'https://example.com/policy3.pdf')
    admin_uuid = get_user(email='admin@admin.com')['data']['uuid']
    user_uuid = get_user(email='user@user.com')['data']['uuid']
    policy1_uuid = get_policy(name='Policy 1')['data']['uuid']
    policy2_uuid = get_policy(name='Policy 2')['data']['uuid']
    policy3_uuid = get_policy(name='Policy 3')['data']['uuid']
    create_assignment(admin_uuid, policy1_uuid, 1)
    create_assignment(user_uuid, policy2_uuid, 2)
    create_assignment(user_uuid, policy3_uuid, 3)