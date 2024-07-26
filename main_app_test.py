import os
import csv
import bcrypt
import requests
import pandas as pd
import streamlit as st
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

st.set_page_config(page_title="Hospital Accreditation Management System")

USERS_CSV_URL = "https://github.com/ashoka-swiftclaims/test/blob/31587228e328108e009f288174371e68319324dd/users.csv"
DOCUMENTS_CSV_URL = "https://github.com/ashoka-swiftclaims/test/blob/cd8d1d7c2c384568c795a661bdc8639939d9730e/documents.csv"
NOTIFICATIONS_CSV_URL = "https://github.com/ashoka-swiftclaims/test/blob/2182a43ac0d091b7bbf6f52b41d68f4f26a793e3/notifications.csv"

UPLOADS_DIR = "main"

# Helper functions to interact with CSV files
def read_csv(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return pd.read_csv(pd.compat.StringIO(response.text)).to_dict(orient='records')
    except (requests.exceptions.RequestException, pd.errors.EmptyDataError):
        return []

def write_csv(file_path, data):
    df = pd.DataFrame(data)
    df.to_csv(file_path, index=False)

def read_csv_from_file(file_path, columns):
    if not os.path.exists(file_path):
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(columns)
    try:
        return pd.read_csv(file_path).to_dict(orient='records')
    except pd.errors.EmptyDataError:
        return []

def write_csv_to_file(file_path, data):
    df = pd.DataFrame(data)
    df.to_csv(file_path, index=False)

# User Management Functions
def create_user(username: str, email: str, password: str, is_admin: bool = False):
    users_data = read_csv_from_file("users.csv", ['id', 'username', 'email', 'hashed_password', 'is_admin'])
    st.success(users_data)
    quit()
    if any(user['username'] == username or user['email'] == email for user in users_data):
        return None
    new_id = max(int(user['id']) for user in users_data) + 1 if users_data else 1
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    new_user = {
        'id': new_id,
        'username': username,
        'email': email,
        'hashed_password': hashed_password,
        'is_admin': is_admin
    }
    users_data.append(new_user)
    write_csv_to_file("users.csv", users_data)
    return new_user

def authenticate_user(username: str, password: str):
    users_data = read_csv_from_file("users.csv", ['id', 'username', 'email', 'hashed_password', 'is_admin'])
    user = next((user for user in users_data if user['username'] == username), None)
    if user and bcrypt.checkpw(password.encode(), user['hashed_password'].encode()):
        return user
    return None

# Notification Management Functions
def add_notification(user_id: int, message: str):
    notifications_data = read_csv_from_file("notifications.csv", ['id', 'message', 'time', 'user_id'])
    new_id = max(int(notification['id']) for notification in notifications_data) + 1 if notifications_data else 1
    new_notification = {
        'id': new_id,
        'message': message,
        'time': datetime.utcnow().isoformat(),
        'user_id': user_id
    }
    notifications_data.append(new_notification)
    write_csv_to_file("notifications.csv", notifications_data)

def send_email_notification(to_email, subject, message):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "your_email@gmail.com"
    smtp_password = "your_password"

    msg = MIMEMultipart()
    msg['From'] = smtp_username
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, to_email, msg.as_string())
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Streamlit App Functions
def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("User Type", ["Regular", "Administrator"])
    if st.button("Login"):
        if not username or not password:
            st.error("Please enter both username, password")
        else:
            user = authenticate_user(username, password)
            if user:
                st.session_state['user'] = {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'is_admin': user['is_admin']
                }
                st.success("Login successful")
                st.experimental_rerun()
            else:
                st.error("Invalid username or password")

def register():
    st.subheader("Register")
    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    role = st.selectbox("User Type", ["Regular", "Administrator"])
    is_admin = True if role == "Administrator" else False
    if st.button("Register"):
        if not username or not email or not password:
            st.error("All fields are required")
        else:
            user = create_user(username, email, password, is_admin)
            if user:
                st.success("Registration successful")
                st.experimental_rerun()
            else:
                st.error("Username or email already exists")

def dashboard():
    if 'user' not in st.session_state:
        st.error("You need to log in first")
        return
    user = st.session_state['user']

    if user['is_admin']:
        st.subheader("Admin Dashboard")
        st.write(f"Welcome {user['username']}")
        st.subheader("User Management")
        manage_users()
        st.subheader("Update Accreditation Status")
        update_accreditation_status()
        st.subheader("Manage Providers")
        manage_providers()
        st.subheader("Statistics and Reports")
        system_statistics_and_reports()
    else:
        st.subheader("User Dashboard")
        st.write(f"Welcome {user['username']}")
        st.subheader("Accreditation Status Tracking")
        accreditation_status_tracking()
        st.subheader("Document Management")
        document_management()

    st.subheader("Notifications")
    notifications()

def manage_users():
    users_data = read_csv_from_file("users.csv", ['id', 'username', 'email', 'hashed_password', 'is_admin'])
    st.write("List of users:")
    for user in users_data:
        st.write(f"Username: {user['username']}, Email: {user['email']}, Admin: {user['is_admin']}")
        if st.button(f"Delete {user['username']}", key=f"delete_{user['id']}"):
            users_data = [u for u in users_data if u['id'] != user['id']]
            write_csv_to_file("users.csv", users_data)
            st.success(f"User {user['username']} deleted")
            st.experimental_rerun()

def update_accreditation_status():
    providers = ["Insurance A", "Insurance B", "Insurance C", "Insurance D"]
    status_options = ["Pending", "In Progress", "Approved", "Rejected"]
    provider = st.selectbox("Select Provider", providers)
    new_status = st.selectbox("Select New Status", status_options)
    if st.button("Update Status"):
        st.success(f"Status of {provider} updated to {new_status}")
        user_id = st.session_state['user']['id']
        add_notification(user_id, f"Status of {provider} updated to {new_status}")
        send_email_notification(
            "recipient_email@example.com",
            "Accreditation Status Update",
            f"The status of {provider} has been updated to {new_status}."
        )

def manage_providers():
    providers = ["Insurance A", "Insurance B", "Insurance C", "Insurance D"]
    new_provider = st.text_input("Add New Provider")
    if st.button("Add Provider"):
        if new_provider not in providers:
            providers.append(new_provider)
            st.success(f"Provider {new_provider} added")
        else:
            st.error(f"Provider {new_provider} already exists")
    provider_to_delete = st.selectbox("Select Provider to Delete", providers)
    if st.button("Delete Provider"):
        if provider_to_delete in providers:
            providers.remove(provider_to_delete)
            st.success(f"Provider {provider_to_delete} deleted")
        else:
            st.error(f"Provider {provider_to_delete} not found")

def system_statistics_and_reports():
    st.write("Total Users: 10")
    st.write("Total Documents: 25")
    st.write("Total Providers: 4")

def accreditation_status_tracking():
    accreditation_data = [
        {"Provider": "Insurance A", "Status": "Pending"},
        {"Provider": "Insurance B", "Status": "In Progress"},
        {"Provider": "Insurance C", "Status": "Approved"},
        {"Provider": "Insurance D", "Status": "Rejected"}
    ]

    filter_status = st.selectbox("Filter by Status", ["All", "Pending", "In Progress", "Approved", "Rejected"])

    if filter_status != "All":
        filtered_data = [acc for acc in accreditation_data if acc["Status"] == filter_status]
    else:
        filtered_data = accreditation_data

    st.table(filtered_data)

def document_management():
    user_id = st.session_state['user']['id']
    documents_data = read_csv_from_file("documents.csv", ['id', 'provider', 'file_name', 'file_path', 'user_id'])
    providers = ["Insurance A", "Insurance B", "Insurance C", "Insurance D"]
    provider = st.selectbox("Associate with Provider", providers)

    uploaded_file = st.file_uploader("Choose a file", type=["pdf", "docx"], accept_multiple_files=False)
    if uploaded_file is not None:
        if uploaded_file.size > 2 * 1024 * 1024:
            st.error("File size should not exceed 2 MB")
        else:
            file_name = uploaded_file.name
            file_path = os.path.join(UPLOADS_DIR, file_name)
            os.makedirs(UPLOADS_DIR, exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            new_id = max(int(doc['id']) for doc in documents_data) + 1 if documents_data else 1
            new_doc = {
                'id': new_id,
                'provider': provider,
                'file_name': file_name,
                'file_path': file_path,
                'user_id': user_id
            }
            documents_data.append(new_doc)
            write_csv_to_file("documents.csv", documents_data)
            st.success("File uploaded successfully")

    st.subheader("Manage Documents")
    user_documents = [doc for doc in documents_data if doc['user_id'] == user_id]

    if not user_documents:
        st.write("No documents found.")
    else:
        for doc in user_documents:
            st.write(f"Provider: {doc['provider']}, File: {doc['file_name']}")
            col1, col2 = st.columns(2)
            with col1:
                if st.button(f"Delete {doc['file_name']}", key=f"delete_{doc['id']}"):
                    os.remove(doc['file_path'])
                    documents_data = [d for d in documents_data if d['id'] != doc['id']]
                    write_csv_to_file("documents.csv", documents_data)
                    st.success(f"{doc['file_name']} deleted")
                    st.experimental_rerun()
            with col2:
                if st.button(f"Replace {doc['file_name']}", key=f"replace_{doc['id']}"):
                    st.session_state['replace_doc'] = doc['id']

        if 'replace_doc' in st.session_state:
            doc_id = st.session_state['replace_doc']
            replacement_file = st.file_uploader(f"Replace Document", type=["pdf", "docx"], key=f"replace_file_{doc_id}")
            if replacement_file is not None:
                if replacement_file.size > 2 * 1024 * 1024:
                    st.error("File size should not exceed 2 MB")
                else:
                    doc_to_replace = next(doc for doc in documents_data if doc['id'] == doc_id)
                    os.makedirs(UPLOADS_DIR, exist_ok=True)
                    os.remove(doc_to_replace['file_path'])
                    new_file_name = replacement_file.name
                    new_file_path = os.path.join(UPLOADS_DIR, new_file_name)
                    with open(new_file_path, "wb") as f:
                        f.write(replacement_file.getbuffer())

                    doc_to_replace['file_name'] = new_file_name
                    doc_to_replace['file_path'] = new_file_path
                    write_csv_to_file("documents.csv", documents_data)
                    st.success("File replaced successfully")
                    del st.session_state['replace_doc']
                    st.experimental_rerun()

def notifications():
    user_id = st.session_state['user']['id']
    notifications_data = read_csv_from_file("notifications.csv", ['id', 'message', 'time', 'user_id'])
    user_notifications = [notif for notif in notifications_data if notif['user_id'] == user_id]
    if not user_notifications:
        st.write("No notifications available.")
    for notification in user_notifications:
        st.write(f"{notification['time']}: {notification['message']}")

# Main application
st.markdown("<h1 style='text-align: center; font-size: 24px;'>Hospital Accreditation Management System</h1>", unsafe_allow_html=True)
page = st.sidebar.radio(" ", ["Home", "Dashboard"])
if page == "Home":
    form_option = st.selectbox("Select", ["Login", "Register"])
    if form_option == "Login":
        login()
    elif form_option == "Register":
        register()
elif page == "Dashboard":
    dashboard()
