from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
import bcrypt
import os
import smtplib
import streamlit as st

st.set_page_config(page_title="Hospital Accreditation Management System")

DATABASE_URL = "sqlite:///./hospital_accreditation.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, index=True)
    file_name = Column(String)
    file_path = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship('User')

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    message = Column(String)
    time = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship('User')

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def create_user(db: Session, username: str, email: str, password: str, is_admin: bool = False):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db_user = User(username=username, email=email, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    try:
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError:
        db.rollback()
        return None

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if user and bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        return user
    return None

def send_email_notification(to_email, subject, message):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "ashokatk@gmail.com"
    smtp_password = "8792940494"

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

def add_notification(db: Session, user_id: int, message: str):
    new_notification = Notification(message=message, user_id=user_id)
    db.add(new_notification)
    db.commit()
    # Debugging statement
    print(f"Notification added: {message}")

def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("User Type", ["Regular", "Administrator"])
    if st.button("Login"):
        if not username or not password:
            st.error("Please enter both username, password")
        else:
            db = SessionLocal()
            user = authenticate_user(db, username, password)
            if user:
                st.session_state['user'] = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin
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
            db = SessionLocal()
            user = create_user(db, username, email, password, is_admin)
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
    db = SessionLocal()
    users = db.query(User).all()
    st.write("List of users:")
    for user in users:
        st.write(f"Username: {user.username}, Email: {user.email}, Admin: {user.is_admin}")
        if st.button(f"Delete {user.username}"):
            db.delete(user)
            db.commit()
            st.success(f"User {user.username} deleted")
            st.experimental_rerun()

def update_accreditation_status():
    db = SessionLocal()
    providers = ["Insurance A", "Insurance B", "Insurance C", "Insurance D"]
    status_options = ["Pending", "In Progress", "Approved", "Rejected"]
    provider = st.selectbox("Select Provider", providers)
    new_status = st.selectbox("Select New Status", status_options)
    if st.button("Update Status"):
        st.success(f"Status of {provider} updated to {new_status}")
        user_id = st.session_state['user']['id']
        add_notification(db, user_id, f"Status of {provider} updated to {new_status}")
        send_email_notification(
            "ashokatk@gmail.com",
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
    db = SessionLocal()
    user_id = st.session_state['user']['id']
    providers = ["Insurance A", "Insurance B", "Insurance C", "Insurance D"]
    provider = st.selectbox("Associate with Provider", providers)

    uploaded_file = st.file_uploader("Choose a file", type=["pdf", "docx"], accept_multiple_files=False)
    if uploaded_file is not None:
        if uploaded_file.size > 2 * 1024 * 1024:
            st.error("File size should not exceed 2 MB")
        else:
            file_name = uploaded_file.name
            file_path = os.path.join("uploads", file_name)
            # Ensure the uploads directory exists
            os.makedirs("uploads", exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            new_doc = Document(provider=provider, file_name=file_name, file_path=file_path, user_id=user_id)
            db.add(new_doc)
            db.commit()
            st.success("File uploaded successfully")

    st.subheader("Manage Documents")
    documents = db.query(Document).filter_by(user_id=user_id).all()

    if not documents:
        st.write("No documents found.")
    else:
        for doc in documents:
            st.write(f"Provider: {doc.provider}, File: {doc.file_name}")
            col1, col2 = st.columns(2)
            with col1:
                if st.button(f"Delete {doc.file_name}", key=f"delete_{doc.id}"):
                    os.remove(doc.file_path)
                    db.delete(doc)
                    db.commit()
                    st.success(f"{doc.file_name} deleted")
                    st.experimental_rerun()
            with col2:
                if st.button(f"Replace {doc.file_name}", key=f"replace_{doc.id}"):
                    st.session_state['replace_doc'] = doc.id

        if 'replace_doc' in st.session_state:
            doc_id = st.session_state['replace_doc']
            replacement_file = st.file_uploader(f"Replace Document", type=["pdf", "docx"], key=f"replace_file_{doc_id}")
            if replacement_file is not None:
                if replacement_file.size > 2 * 1024 * 1024:
                    st.error("File size should not exceed 2 MB")
                else:
                    doc_to_replace = db.query(Document).filter_by(id=doc_id).first()
                    # Ensure the uploads directory exists
                    os.makedirs("uploads", exist_ok=True)
                    os.remove(doc_to_replace.file_path)
                    new_file_name = replacement_file.name
                    new_file_path = os.path.join("uploads", new_file_name)
                    with open(new_file_path, "wb") as f:
                        f.write(replacement_file.getbuffer())

                    doc_to_replace.file_name = new_file_name
                    doc_to_replace.file_path = new_file_path
                    db.commit()
                    st.success("File replaced successfully")
                    del st.session_state['replace_doc']
                    st.experimental_rerun()

def notifications():
    db = SessionLocal()
    user_id = st.session_state['user']['id']
    user_notifications = db.query(Notification).filter_by(user_id=user_id).all()
    if not user_notifications:
        # Debugging statement
        st.write("No notifications available.")
    for notification in user_notifications:
        st.write(f"{notification.time}: {notification.message}")

# ---------------------------------
# Main application
# # for testing purposes
# st.session_state['user'] = {'id': 1, 'username': 'ashoka', 'email': 'ashokatk@gmail.com', 'is_admin': True} # Set to False for regular user testing
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

