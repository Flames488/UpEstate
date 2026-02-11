"""Management script for database migrations and other tasks"""

import os
from flask.cli import FlaskGroup
from flask_migrate import Migrate, upgrade
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.lead import Lead

# Initialize app and extensions
app = create_app()
cli = FlaskGroup(app)
Migrate(app, db)


@cli.command("init-db")
def init_db():
    """Initialize the database"""
    with app.app_context():
        db.create_all()
        print("✅ Database initialized successfully!")


@cli.command("drop-db")
def drop_db():
    """Drop all database tables"""
    confirmation = input("⚠️  Are you sure you want to drop all tables? (yes/no): ").lower()
    
    if confirmation == 'yes':
        with app.app_context():
            db.drop_all()
            print("✅ Database dropped successfully!")
    else:
        print("❌ Operation cancelled.")


@cli.command("seed-db")
def seed_db():
    """Seed the database with sample data"""
    with app.app_context():
        # Check if sample user already exists
        existing_user = User.query.filter_by(email="admin@realestatepro.com").first()
        if existing_user:
            print("⚠️  Sample user already exists. Skipping user creation.")
        else:
            # Create a sample user
            user = User(
                full_name="John Doe",
                email="admin@realestatepro.com",
                phone="+1234567890",
                company="RealEstate Pro",
                role="admin"
            )
            user.set_password("admin123")
            db.session.add(user)
            print("✅ Sample user created.")
        
        # Create sample leads if they don't exist
        sample_emails = ["alice@example.com", "bob@example.com", "carol@example.com"]
        existing_leads = Lead.query.filter(Lead.email.in_(sample_emails)).count()
        
        if existing_leads == 0:
            leads = [
                Lead(
                    name="Alice Johnson",
                    email="alice@example.com",
                    phone="+1234567891",
                    property_type="residential",
                    budget="250k-500k",
                    timeline="short",
                    message="Looking for a 3-bedroom house",
                    score=85,
                    status="new"
                ),
                Lead(
                    name="Bob Smith",
                    email="bob@example.com",
                    phone="+1234567892",
                    property_type="commercial",
                    budget="over-1m",
                    timeline="immediate",
                    message="Need office space downtown",
                    score=92,
                    status="qualified"
                ),
                Lead(
                    name="Carol White",
                    email="carol@example.com",
                    phone="+1234567893",
                    property_type="land",
                    budget="100k-250k",
                    timeline="long",
                    message="Interested in vacant land",
                    score=45,
                    status="contacted"
                )
            ]
            
            for lead in leads:
                db.session.add(lead)
            
            print("✅ Sample leads created.")
        else:
            print("⚠️  Sample leads already exist. Skipping lead creation.")
        
        db.session.commit()
        print("✅ Database seeded successfully!")


@cli.command("create-admin")
def create_admin():
    """Create an admin user"""
    print("\n🔧 Create Admin User")
    print("-" * 30)
    
    email = input("Enter admin email: ").strip()
    full_name = input("Enter full name: ").strip()
    password = input("Enter password: ").strip()
    
    if not email or not full_name or not password:
        print("❌ All fields are required!")
        return
    
    with app.app_context():
        # Check if user exists
        if User.query.filter_by(email=email).first():
            print(f"❌ User with email '{email}' already exists!")
            return
        
        user = User(
            full_name=full_name,
            email=email,
            phone="+0000000000",
            company="RealEstate Pro",
            role="admin"
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        print(f"✅ Admin user created successfully: {email}")


@cli.command("migrate-db")
def migrate_db():
    """Apply any pending database migrations"""
    print("🔄 Applying database migrations...")
    
    with app.app_context():
        try:
            upgrade()
            print("✅ Database migrations applied successfully!")
        except Exception as e:
            print(f"❌ Migration failed: {str(e)}")
            raise


@cli.command("check-migrations")
def check_migrations():
    """Check if there are pending migrations"""
    print("🔍 Checking for pending migrations...")
    
    with app.app_context():
        from flask_migrate import status as migration_status
        migration_status()
        print("✅ Migration check completed!")


@cli.command("reset-db")
def reset_db():
    """Reset database (drop, create, seed)"""
    confirmation = input("⚠️  This will drop ALL data and recreate the database. Continue? (yes/no): ").lower()
    
    if confirmation == 'yes':
        with app.app_context():
            # Drop all tables
            db.drop_all()
            print("✅ Database dropped.")
            
            # Create all tables
            db.create_all()
            print("✅ Database recreated.")
            
            # Seed with sample data
            seed_db()
    else:
        print("❌ Operation cancelled.")


# Add this for auto-migration on deploy
def migrate_on_startup():
    """Automatically run migrations when app starts (for production)"""
    with app.app_context():
        try:
            # Only run migrations in production environment
            if os.environ.get('FLASK_ENV') == 'production':
                print("🔄 Running database migrations on startup...")
                upgrade()
                print("✅ Database migrations completed!")
        except Exception as e:
            print(f"⚠️  Auto-migration failed: {e}")


# Call auto-migration if environment variable is set
if os.environ.get('AUTO_MIGRATE', 'false').lower() == 'true':
    migrate_on_startup()


if __name__ == "__main__":
    cli()