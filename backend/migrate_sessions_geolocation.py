"""
Database migration script to add geolocation and risk assessment fields to sessions table.

Run this script ONCE to update your existing database:
    python migrate_sessions_geolocation.py

New columns added:
- latitude (Float): GPS latitude from browser geolocation
- longitude (Float): GPS longitude from browser geolocation
- risk_score (Float): Risk assessment score 0.0-1.0
- status (String): Session status (normal/suspicious/critical)
- risk_factors (Text): JSON string of detected risk factors
"""

from sqlalchemy import Column, Float, String, Text, create_engine, inspect
from sqlalchemy.orm import sessionmaker
import os
from pathlib import Path

# Database path
DB_PATH = Path(__file__).parent / "insider.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

def migrate_sessions_table():
    """Add new columns to sessions table if they don't exist"""
    engine = create_engine(DATABASE_URL, echo=True)
    
    # Check existing columns
    inspector = inspect(engine)
    existing_columns = [col['name'] for col in inspector.get_columns('sessions')]
    
    print(f"Existing columns in sessions table: {existing_columns}")
    
    # Define new columns to add
    new_columns = {
        'latitude': 'REAL',
        'longitude': 'REAL',
        'risk_score': 'REAL DEFAULT 0.0 NOT NULL',
        'status': "TEXT DEFAULT 'normal' NOT NULL",
        'risk_factors': 'TEXT'
    }
    
    # Add missing columns
    with engine.connect() as conn:
        for col_name, col_type in new_columns.items():
            if col_name not in existing_columns:
                try:
                    sql = f'ALTER TABLE sessions ADD COLUMN {col_name} {col_type}'
                    print(f"Executing: {sql}")
                    conn.execute(text(sql))
                    conn.commit()
                    print(f"✅ Added column: {col_name}")
                except Exception as e:
                    print(f"❌ Error adding column {col_name}: {e}")
            else:
                print(f"⏭️  Column {col_name} already exists")
    
    print("\n✅ Migration complete!")
    print("Sessions table now supports:")
    print("  - GPS coordinates (latitude, longitude)")
    print("  - Risk scoring (risk_score, status)")
    print("  - Risk factors tracking (risk_factors)")


if __name__ == "__main__":
    from sqlalchemy import text
    
    print("=" * 60)
    print("DATABASE MIGRATION: Sessions Geolocation & Risk Assessment")
    print("=" * 60)
    
    if not DB_PATH.exists():
        print(f"❌ Database not found: {DB_PATH}")
        print("Creating new database with init_db.py instead...")
        exit(1)
    
    migrate_sessions_table()
    
    print("\n" + "=" * 60)
    print("You can now use the enhanced login tracking features!")
    print("=" * 60)
