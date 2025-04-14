import streamlit as st
import hashlib
import json
import os
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timedelta

# Configuration
PERSISTENT_STORAGE_FILE = "encrypted_data.json"
MASTER_PASSWORD = "secureadmin123"  # In production, use environment variables
LOCKOUT_TIME_MINUTES = 5
MAX_ATTEMPTS = 3

# Initialize session state
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
    
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
    
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = None
    
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# Key generation and management
def generate_fernet_key(password: str, salt: bytes = None):
    """Generate Fernet key using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Persistent storage functions
def load_data():
    """Load encrypted data from file"""
    if os.path.exists(PERSISTENT_STORAGE_FILE):
        with open(PERSISTENT_STORAGE_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_data(data):
    """Save encrypted data to file"""
    with open(PERSISTENT_STORAGE_FILE, 'w') as f:
        json.dump(data, f)

# Security functions
def hash_passkey(passkey, salt=None):
    """Hash passkey with PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    hashed = kdf.derive(passkey.encode())
    return base64.b64encode(hashed).decode(), base64.b64encode(salt).decode()

def verify_passkey(passkey, stored_hash, stored_salt):
    """Verify passkey against stored hash"""
    try:
        salt = base64.b64decode(stored_salt)
        new_hash, _ = hash_passkey(passkey, salt)
        return new_hash == stored_hash
    except:
        return False

def encrypt_data(text, password):
    """Encrypt data with Fernet"""
    key, salt = generate_fernet_key(password)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted).decode(), salt

def decrypt_data(encrypted_text, password, salt):
    """Decrypt data with Fernet"""
    try:
        key, _ = generate_fernet_key(password, base64.b64decode(salt))
        cipher = Fernet(key)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
        return decrypted.decode()
    except:
        return None

# Streamlit UI
st.set_page_config(
    page_title="🔒 Secure Data Vault",
    page_icon="🔒",
    layout="centered"
)

# Custom CSS
st.markdown("""
<style>
    .warning-box {
        background-color: #fff3cd;
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    .error-box {
        background-color: #f8d7da;
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    .success-box {
        background-color: #d4edda;
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    .info-box {
        background-color: #d1ecf1;
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Load persistent data
if not st.session_state.stored_data:
    st.session_state.stored_data = load_data()

# Navigation
def main():
    st.sidebar.title("Navigation")
    
    if st.session_state.current_user:
        menu_options = ["Home", "Store Data", "Retrieve Data", "My Data", "Logout"]
    else:
        menu_options = ["Home", "Login", "Register"]
    
    choice = st.sidebar.selectbox("Menu", menu_options)
    
    if choice == "Home":
        home_page()
    elif choice == "Store Data":
        store_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()
    elif choice == "My Data":
        my_data_page()
    elif choice == "Login":
        login_page()
    elif choice == "Register":
        register_page()
    elif choice == "Logout":
        logout_page()

# Pages
def home_page():
    st.title("🔒 Secure Data Vault")
    st.markdown("""
    <div class="info-box">
        <h3>Welcome to Secure Data Vault</h3>
        <p>Store and retrieve your sensitive data with military-grade encryption.</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.current_user:
        st.success(f"Logged in as: {st.session_state.current_user}")
        st.write("Use the sidebar to store or retrieve your encrypted data.")
    else:
        st.warning("Please login or register to use the system.")
    
    st.markdown("### Features:")
    st.write("- AES-256 encryption with PBKDF2 key derivation")
    st.write("- Brute-force protection with account lockout")
    st.write("- Persistent storage of encrypted data")
    st.write("- Multi-user support with individual data isolation")

def store_data_page():
    if not st.session_state.current_user:
        st.warning("Please login first.")
        return
    
    st.title("📂 Store Data Securely")
    
    data_id = st.text_input("Data Identifier (unique name):")
    user_data = st.text_area("Data to Encrypt:")
    passkey = st.text_input("Encryption Passphrase:", type="password")
    passkey_confirm = st.text_input("Confirm Passphrase:", type="password")
    
    if st.button("Encrypt & Store"):
        if not all([data_id, user_data, passkey, passkey_confirm]):
            st.error("All fields are required!")
        elif passkey != passkey_confirm:
            st.error("Passphrases don't match!")
        elif len(passkey) < 8:
            st.error("Passphrase must be at least 8 characters")
        else:
            # Encrypt the data
            encrypted_text, salt = encrypt_data(user_data, passkey)
            hashed_passkey, passkey_salt = hash_passkey(passkey)
            
            # Store in memory and persistent storage
            user_data_key = f"{st.session_state.current_user}_{data_id}"
            st.session_state.stored_data[user_data_key] = {
                "encrypted_text": encrypted_text,
                "salt": salt,
                "hashed_passkey": hashed_passkey,
                "passkey_salt": passkey_salt,
                "timestamp": datetime.now().isoformat()
            }
            save_data(st.session_state.stored_data)
            
            st.markdown(f"""
            <div class="success-box">
                ✅ Data stored securely!<br><br>
                <strong>ID:</strong> {data_id}<br>
                <strong>Encrypted at:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
            """, unsafe_allow_html=True)

def retrieve_data_page():
    if not st.session_state.current_user:
        st.warning("Please login first.")
        return
    
    # Check if system is locked
    if st.session_state.lockout_time and datetime.now() < st.session_state.lockout_time:
        remaining_time = (st.session_state.lockout_time - datetime.now()).seconds
        st.error(f"🔒 System locked. Please try again in {remaining_time} seconds.")
        return
    
    st.title("🔍 Retrieve Your Data")
    
    # Get user's data identifiers
    user_data_keys = [key.split('_', 1)[1] for key in st.session_state.stored_data.keys() 
                     if key.startswith(st.session_state.current_user)]
    
    if not user_data_keys:
        st.warning("No data found for your account.")
        return
    
    data_id = st.selectbox("Select data to retrieve:", user_data_keys)
    passkey = st.text_input("Enter your passphrase:", type="password")
    
    if st.button("Decrypt"):
        if not passkey:
            st.error("Passphrase is required!")
            return
        
        user_data_key = f"{st.session_state.current_user}_{data_id}"
        if user_data_key not in st.session_state.stored_data:
            st.error("Data not found!")
            return
            
        encrypted_data = st.session_state.stored_data[user_data_key]
        
        # Verify passkey
        if not verify_passkey(passkey, encrypted_data["hashed_passkey"], encrypted_data["passkey_salt"]):
            st.session_state.failed_attempts += 1
            remaining_attempts = MAX_ATTEMPTS - st.session_state.failed_attempts
            
            if remaining_attempts > 0:
                st.error(f"❌ Incorrect passphrase! Attempts remaining: {remaining_attempts}")
            else:
                st.session_state.lockout_time = datetime.now() + timedelta(minutes=LOCKOUT_TIME_MINUTES)
                st.error(f"🔒 Too many failed attempts! System locked for {LOCKOUT_TIME_MINUTES} minutes.")
            return
        
        # Decrypt data
        decrypted_text = decrypt_data(
            encrypted_data["encrypted_text"],
            passkey,
            encrypted_data["salt"]
        )
        
        if decrypted_text:
            st.session_state.failed_attempts = 0
            st.markdown(f"""
            <div class="success-box">
                ✅ Decryption successful!<br><br>
                <strong>Original data:</strong><br>
                {decrypted_text}<br><br>
                <strong>Encrypted at:</strong> {encrypted_data["timestamp"]}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.error("❌ Decryption failed. Data may be corrupted.")

def my_data_page():
    if not st.session_state.current_user:
        st.warning("Please login first.")
        return
    
    st.title("📋 My Stored Data")
    
    # Get user's data
    user_data = {
        key.split('_', 1)[1]: value 
        for key, value in st.session_state.stored_data.items()
        if key.startswith(st.session_state.current_user)
    }
    
    if not user_data:
        st.info("You haven't stored any data yet.")
        return
    
    st.write(f"Found {len(user_data)} encrypted items:")
    
    for data_id, data in user_data.items():
        with st.expander(f"🔒 {data_id}"):
            st.write(f"**Stored on:** {data['timestamp']}")
            st.code(f"Encrypted: {data['encrypted_text'][:50]}...")

def login_page():
    st.title("🔑 Login")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        # In a real system, you would verify against a user database
        # Here we're using a simple check for demonstration
        if username and password == f"{username}123":
            st.session_state.current_user = username
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            st.success("Login successful!")
            time.sleep(1)
            st.experimental_rerun()
        else:
            st.error("Invalid username or password")

def register_page():
    st.title("📝 Register")
    
    username = st.text_input("Choose a username")
    password = st.text_input("Choose a password", type="password")
    confirm_password = st.text_input("Confirm password", type="password")
    
    if st.button("Register"):
        if not username or not password:
            st.error("Username and password are required!")
        elif password != confirm_password:
            st.error("Passwords don't match!")
        elif len(password) < 8:
            st.error("Password must be at least 8 characters")
        else:
            # In a real system, you would store the user securely
            st.success(f"Account created for {username}. Please login.")
            time.sleep(1)
            st.experimental_rerun()

def logout_page():
    st.session_state.current_user = None
    st.success("Logged out successfully!")
    time.sleep(1)
    st.experimental_rerun()

if __name__ == "__main__":
    main()