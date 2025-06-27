import uuid
import hashlib
import time

def generate_uuid():
    return str(uuid.uuid4())

def generate_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_timestamp():
    return int(time.time())
    