import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import time

# Initialize session state variables if they don't exist
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    
if 'cipher' not in st.session_state:
    st.session_state.cipher = Fernet(st.session_state.key)
    
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
    
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
    
if 'last_failure_time' not in st.session_state:
    st.session_state.last_failure_time = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    # We don't actually use the passkey for encryption, just for authentication
    # Encryption is done with the Fernet key
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    
    # Check if the encrypted_text exists in stored_data
    if encrypted_text in st.session_state.stored_data:
        # Check if the passkey matches
        if st.session_state.stored_data[encrypted_text]["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            try:
                return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
            except Exception:
                return None
    
    # If we get here, either the encrypted_text doesn't exist or the passkey is wrong
    st.session_state.failed_attempts += 1
    st.session_state.last_failure_time = time.time()
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Check if we need to force a reauthorization
if st.session_state.failed_attempts >= 3 and choice != "Login":
    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
    choice = "Login"

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    # Display some helpful information
    st.info("""
    ## How to use this app:
    
    1. **Store Data**: Enter your text and a passkey to encrypt and store it
    2. **Retrieve Data**: Enter the encrypted text and the correct passkey to decrypt it
    3. **Security**: After 3 failed attempts, you'll need to reauthorize
    
    All data is stored in memory and will be lost when the app is restarted.
    """)

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            st.session_state.stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
            st.info("Copy the encrypted text above to retrieve your data later.")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    # Show current failed attempts status
    if st.session_state.failed_attempts > 0:
        st.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Decryption successful!")
                st.subheader("Decrypted Data:")
                st.write(decrypted_text)
            else:
                remaining_attempts = 3 - st.session_state.failed_attempts
                if remaining_attempts > 0:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining_attempts}")
                else:
                    st.error("❌ Too many failed attempts!")
                    st.warning("🔒 Redirecting to Login Page for reauthorization...")
                    time.sleep(1)  # Short delay for user to see the message
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")
    
    # Add a note about the master password
    st.info("For this demo, the master password is 'admin123'")

    if st.button("Login"):
        if login_pass == "admin123":  # For a real system, use a more secure approach
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Home...")
            time.sleep(1)  # Short delay for user to see the message
            st.rerun()
        else:
            st.error("❌ Incorrect password!")

# Show data statistics in the sidebar
st.sidebar.subheader("System Stats")
st.sidebar.write(f"📊 Stored entries: {len(st.session_state.stored_data)}")
st.sidebar.write(f"🔐 Failed attempts: {st.session_state.failed_attempts}/3")

# Footer
st.sidebar.markdown("---")
st.sidebar.write("👨‍💻 Secure Data Encryption System")
st.sidebar.write("🔒 Your data is encrypted with Fernet")