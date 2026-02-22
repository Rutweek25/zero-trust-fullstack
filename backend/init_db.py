"""
Create database with proper schema and seed with users
"""
import os
from datetime import datetime, timezone
from time_utils import now_ist
from passlib.context import CryptContext

# Import models and database
from database import Base, engine, SessionLocal
from models import User, Device, Telemetry, Session, Log, LockUnlockRequest

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def init_database():
    """Initialize database with fresh schema"""
    print("="*70)
    print("INITIALIZING DATABASE WITH PROPER SCHEMA")
    print("="*70)
    
    # Drop all tables first
    print("\n1. Dropping existing tables...")
    Base.metadata.drop_all(bind=engine)
    print("   ✓ Old schema removed")
    
    # Create fresh tables
    print("\n2. Creating fresh schema...")
    Base.metadata.create_all(bind=engine)
    print("   ✓ New schema created")
    
    # Get database session
    db = SessionLocal()
    
    # Create SuperAdmin user
    print("\n3. Creating superadmin user...")
    superadmin = User(
        username="superadmin",
        name="Super Admin",
        company_email="superadmin@company.com",
        personal_email="superadmin@admin.local",
        password_hash=pwd_context.hash("super@1234"),
        role="superadmin",
        status="active",
        created_at=now_ist()
    )
    db.add(superadmin)
    db.flush()  # Get the ID
    print(f"   ✓ SuperAdmin created: superadmin@company.com / super@1234")
    
    # Create Admin user
    print("\n4. Creating admin user...")
    admin = User(
        username="admin",
        name="Admin User",
        company_email="admin@company.com",
        personal_email="admin@admin.local",
        password_hash=pwd_context.hash("admin@1234"),
        role="admin",
        status="active",
        created_at=now_ist()
    )
    db.add(admin)
    db.flush()
    print(f"   ✓ Admin created: admin@company.com / admin@1234")
    
    # Create regular users for testing
    print("\n5. Creating test users...")
    test_users = [
        {
            "username": "john.doe",
            "name": "John Doe",
            "company_email": "john.doe@company.com",
            "personal_email": "john@example.com",
            "password": "test@1234",
            "role": "user"
        },
        {
            "username": "jane.smith",
            "name": "Jane Smith",
            "company_email": "jane.smith@company.com",
            "personal_email": "jane@example.com",
            "password": "test@1234",
            "role": "user"
        },
        {
            "username": "bob.wilson",
            "name": "Bob Wilson",
            "company_email": "bob.wilson@company.com",
            "personal_email": "bob@example.com",
            "password": "test@1234",
            "role": "user"
        }
    ]
    
    for user_data in test_users:
        user = User(
            username=user_data["username"],
            name=user_data["name"],
            company_email=user_data["company_email"],
            personal_email=user_data["personal_email"],
            password_hash=pwd_context.hash(user_data["password"]),
            role=user_data["role"],
            status="active",
            created_at=now_ist()
        )
        db.add(user)
        print(f"   ✓ {user_data['username']}: {user_data['company_email']}")
    
    # Commit all users
    db.commit()
    
    print("\n" + "="*70)
    print("DATABASE INITIALIZED SUCCESSFULLY")
    print("="*70)
    
    print("\nUsers created:")
    print("  SUPERADMIN: superadmin@company.com / super@1234")
    print("  ADMIN:      admin@company.com / admin@1234")
    print("  TEST:       john.doe@company.com / test@1234")
    print("  TEST:       jane.smith@company.com / test@1234")
    print("  TEST:       bob.wilson@company.com / test@1234")
    
    # Verify schema
    print("\nDatabase tables created:")
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    for table in sorted(tables):
        print(f"  ✓ {table}")
    
    # Verify data
    print("\nData verification:")
    user_count = db.query(User).count()
    print(f"  Total users: {user_count}")
    
    superadmin_check = db.query(User).filter(User.role == "superadmin").first()
    if superadmin_check:
        print(f"  ✓ SuperAdmin verified: {superadmin_check.username}")
    
    db.close()
    
    print("\n✅ Database ready to use!\n")

if __name__ == "__main__":
    init_database()
