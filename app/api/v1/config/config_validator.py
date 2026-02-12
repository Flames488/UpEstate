from app.config.settings import IS_PRODUCTION
import os
import sys

# Core reliability checklist - NEVER optional
CORE_RELIABILITY_VARS = [
    # Authentication & Security
    "SECRET_KEY",           # Django/Flask secret
    "JWT_SECRET_KEY",       # JWT signing
    
    # Data persistence
    "DATABASE_URL",         # Primary database
    
    # Payment processing
    "STRIPE_SECRET_KEY",    # Payment processing
    
    # Operational
    "ALLOWED_HOSTS",        # Security: host validation
]

def validate_core_config():
    """Hard validation for production, warnings for development"""
    missing = []
    
    for var in CORE_RELIABILITY_VARS:
        value = os.getenv(var)
        
        # Special handling for ALLOWED_HOSTS
        if var == "ALLOWED_HOSTS":
            if not value or value.strip() == "":
                missing.append(var)
            elif IS_PRODUCTION and "*" in value:
                print(f"[SECURITY WARNING] ALLOWED_HOSTS contains wildcard '*' in production")
        # Default validation for other vars
        elif not value or value.strip() == "":
            missing.append(var)
    
    if missing:
        message = f"CRITICAL: Missing core reliability variables: {missing}"
        
        if IS_PRODUCTION:
            # Production: Hard fail with clear instructions
            print(f"❌ PRODUCTION FAILURE: {message}", file=sys.stderr)
            print("\n💡 Required for production deployment:", file=sys.stderr)
            for var in missing:
                if var == "DATABASE_URL":
                    print(f"  - {var}: PostgreSQL connection string", file=sys.stderr)
                elif var == "STRIPE_SECRET_KEY":
                    print(f"  - {var}: Get from Stripe Dashboard → Developers → API keys", file=sys.stderr)
                elif var == "JWT_SECRET_KEY":
                    print(f"  - {var}: Generate with: openssl rand -hex 32", file=sys.stderr)
                else:
                    print(f"  - {var}: Required for security/operations", file=sys.stderr)
            raise RuntimeError("Production configuration incomplete")
        else:
            # Development: Warning with guidance
            print(f"\n⚠️  [MVP WARNING] {message}", file=sys.stderr)
            print("   The app will run, but these features will be disabled:", file=sys.stderr)
            
            if "STRIPE_SECRET_KEY" in missing:
                print("   • Payments/Stripe integration", file=sys.stderr)
            if "DATABASE_URL" in missing:
                print("   • Database persistence (using fallback SQLite)", file=sys.stderr)
            if "JWT_SECRET_KEY" in missing:
                print("   • JWT authentication (using insecure fallback)", file=sys.stderr)
            if "SECRET_KEY" in missing:
                print("   • Session security (using insecure fallback)", file=sys.stderr)
            
            print("\n💡 Quick fix for development:", file=sys.stderr)
            print("   Create .env file with:", file=sys.stderr)
            print("   SECRET_KEY='dev-secret-change-in-production'", file=sys.stderr)
            print("   JWT_SECRET_KEY='dev-jwt-secret-change-in-prod'", file=sys.stderr)
            print("   DATABASE_URL='sqlite:///./app.db'", file=sys.stderr)
            print("   STRIPE_SECRET_KEY='sk_test_...' (get test key from Stripe)", file=sys.stderr)
    
    else:
        if IS_PRODUCTION:
            print("✅ Core reliability checklist PASSED", file=sys.stderr)
        else:
            print("✅ Development config OK", file=sys.stderr)

# Auto-run validation on import
validate_core_config()