import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64

# -------------------- Session Storage --------------------
if "users_db" not in st.session_state: st.session_state.users_db = {}
if "data_db" not in st.session_state: st.session_state.data_db = {}
if "logged_in_user" not in st.session_state: st.session_state.logged_in_user = None

# -------------------- Helper Functions --------------------
def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()
def generate_key_from_passkey(passkey): return base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())
def encrypt_data(data, key): return Fernet(key).encrypt(data.encode()).decode()
def decrypt_data(data, key): return Fernet(key).decrypt(data.encode()).decode()

# -------------------- Title --------------------
st.title("🔐 Secure Data Encryption System")

# -------------------- Authentication --------------------
if st.session_state.logged_in_user:
    st.success(f"👋 Logged in as: {st.session_state.logged_in_user}")
    if st.button("Logout"): 
        st.session_state.logged_in_user = None
        st.rerun()
else:
    auth_mode = st.radio("Login or Register", ["Login", "Register"])
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    
    if auth_mode == "Login" and st.button("Login"):
        if user in st.session_state.users_db and st.session_state.users_db[user] == hash_password(pwd):
            st.success("✅ Login successful!")
            st.session_state.logged_in_user = user
            st.rerun()
        else:
            st.error("❌ Invalid username or password!")
    
    elif auth_mode == "Register" and st.button("Register"):
        if user and pwd:
            if user not in st.session_state.users_db:
                st.session_state.users_db[user] = hash_password(pwd)
                st.success("✅ Registered successfully! You are now logged in.")
                # Automatically log the user in after registration
                st.session_state.logged_in_user = user
                st.rerun()
            else:
                st.warning("⚠️ Username already exists!")
        else:
            st.error("❌ Please enter both username and password.")

# -------------------- Encryption & Decryption --------------------
if st.session_state.logged_in_user:
    secret_data = st.text_area("Enter data to encrypt")
    user_key = st.text_input("Secret key", type="password")
    
    if st.button("Encrypt & Save") and secret_data and user_key:
        key = generate_key_from_passkey(user_key)
        encrypted = encrypt_data(secret_data, key)
        st.session_state.data_db[st.session_state.logged_in_user] = {"encrypted": encrypted, "key": key.decode()}
        st.success("✅ Data encrypted!")
        st.code(encrypted)
    
    if st.button("Decrypt Data"):
        user_data = st.session_state.data_db.get(st.session_state.logged_in_user)
        if user_data:
            try:
                decrypted = decrypt_data(user_data["encrypted"], user_data["key"].encode())
                st.success("✅ Decrypted Data:")
                st.code(decrypted)
            except:
                st.error("❌ Decryption failed!")

