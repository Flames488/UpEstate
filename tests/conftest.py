import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import stripe
from flask_jwt_extended import create_access_token
from app import create_app
from app.extensions import db
import os
from faker import Faker
import asyncio
from contextlib import contextmanager

# Initialize Faker for generating test data
fake = Faker()

# Custom pytest marks for organizing tests
def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test (requires external services)"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow-running"
    )
    config.addinivalue_line(
        "markers",
        "db: mark test as database-intensive"
    )
    config.addinivalue_line(
        "markers",
        "auth: mark test as authentication-related"
    )
    config.addinivalue_line(
        "markers",
        "payment: mark test as payment-related"
    )

# Test fixtures for the entire test suite

@pytest.fixture(scope="session")
def app():
    """Create application for testing with enhanced configuration"""
    app = create_app("testing")
    
    # Enhanced test configuration
    app.config.update(
        TESTING=True,
        DEBUG=False,
        SQLALCHEMY_DATABASE_URI=os.getenv("TEST_DATABASE_URI", "sqlite:///:memory:"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        JWT_SECRET_KEY=os.getenv("TEST_JWT_SECRET", "super-secret-test-key-2024"),
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
        STRIPE_SECRET_KEY="sk_test_mock",
        STRIPE_PUBLISHABLE_KEY="pk_test_mock",
        REDIS_URL="redis://localhost:6379/1",
        CACHE_TYPE="SimpleCache",
        CACHE_DEFAULT_TIMEOUT=300,
        MAIL_SUPPRESS_SEND=True,
        MAIL_DEFAULT_SENDER="test@example.com",
        RATE_LIMITING_ENABLED=False,
        ENABLE_API_DOCS=False,
    )

    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Optional: Seed initial test data
        # seed_test_data()
        
        yield app
        
        # Cleanup
        db.session.remove()
        db.drop_all()
        print("Database cleaned up")


@pytest.fixture()
def client(app):
    """Enhanced test client with helper methods"""
    client = app.test_client()
    
    # Add helper methods to client
    def login(self, email="admin@test.com", password="testpass"):
        return self.post('/api/auth/login', json={
            'email': email,
            'password': password
        })
    
    def logout(self):
        return self.post('/api/auth/logout')
    
    def authenticated_get(self, url, token=None, **kwargs):
        headers = kwargs.pop('headers', {})
        if token:
            headers['Authorization'] = f'Bearer {token}'
        return self.get(url, headers=headers, **kwargs)
    
    def authenticated_post(self, url, token=None, **kwargs):
        headers = kwargs.pop('headers', {})
        if token:
            headers['Authorization'] = f'Bearer {token}'
        return self.post(url, headers=headers, **kwargs)
    
    def authenticated_put(self, url, token=None, **kwargs):
        headers = kwargs.pop('headers', {})
        if token:
            headers['Authorization'] = f'Bearer {token}'
        return self.put(url, headers=headers, **kwargs)
    
    def authenticated_delete(self, url, token=None, **kwargs):
        headers = kwargs.pop('headers', {})
        if token:
            headers['Authorization'] = f'Bearer {token}'
        return self.delete(url, headers=headers, **kwargs)
    
    # Add methods to client instance
    client.login = login.__get__(client)
    client.logout = logout.__get__(client)
    client.authenticated_get = authenticated_get.__get__(client)
    client.authenticated_post = authenticated_post.__get__(client)
    client.authenticated_put = authenticated_put.__get__(client)
    client.authenticated_delete = authenticated_delete.__get__(client)
    
    return client


@pytest.fixture()
def db_session(app):
    """Database session with automatic rollback"""
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()
        
        # Create a scoped session
        session = db.create_scoped_session(options={'bind': connection})
        db.session = session
        
        try:
            yield session
        finally:
            transaction.rollback()
            connection.close()
            session.remove()


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture
def mock_user_data():
    """Fixture for test user data with Faker"""
    return {
        "id": fake.uuid4(),
        "username": fake.user_name(),
        "email": fake.email(),
        "password": fake.password(length=12),
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "phone": fake.phone_number(),
        "is_active": True,
        "is_verified": True,
        "role": "user",
        "plan": "free",
        "created_at": fake.date_time_this_year().isoformat(),
        "updated_at": fake.date_time_this_year().isoformat()
    }


@pytest.fixture
def mock_admin_user_data():
    """Fixture for admin user data"""
    return {
        "id": "admin_123",
        "username": "adminuser",
        "email": "admin@example.com",
        "password": "hashed_admin_password",
        "role": "admin",
        "plan": "enterprise",
        "is_active": True,
        "permissions": ["read", "write", "delete", "admin"]
    }


@pytest.fixture
def mock_lead_data():
    """Enhanced fixture for test lead data"""
    return {
        "id": fake.uuid4(),
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.phone_number(),
        "company": fake.company(),
        "job_title": fake.job(),
        "industry": fake.random_element(["tech", "finance", "healthcare", "education"]),
        "source": fake.random_element(["website", "referral", "social", "event"]),
        "source_details": {
            "campaign": fake.word(),
            "medium": fake.word(),
            "content": fake.sentence()
        },
        "notes": fake.paragraph(),
        "status": fake.random_element(["new", "contacted", "qualified", "converted", "lost"]),
        "priority": fake.random_element(["low", "medium", "high"]),
        "assigned_to": None,
        "score": fake.random_int(min=0, max=100),
        "last_contacted": fake.date_time_this_month().isoformat(),
        "created_at": fake.date_time_this_year().isoformat(),
        "metadata": {
            "ip_address": fake.ipv4(),
            "user_agent": fake.user_agent(),
            "landing_page": fake.url()
        }
    }


@pytest.fixture
def mock_payment_data():
    """Enhanced fixture for test payment data"""
    return {
        "id": fake.uuid4(),
        "amount": fake.random_int(min=1000, max=100000),  # $10.00 to $1000.00 in cents
        "currency": fake.random_element(["usd", "eur", "gbp", "cad"]),
        "description": fake.sentence(),
        "customer_email": fake.email(),
        "customer_name": fake.name(),
        "customer_id": f"cus_{fake.uuid4()[:14]}",
        "payment_method": f"pm_{fake.random_element(['card', 'bank'])}_123",
        "payment_method_details": {
            "type": "card",
            "card": {
                "brand": fake.random_element(["visa", "mastercard", "amex"]),
                "last4": fake.random_number(digits=4, fix_len=True),
                "exp_month": fake.random_int(min=1, max=12),
                "exp_year": fake.random_int(min=2024, max=2030)
            }
        },
        "status": fake.random_element(["succeeded", "pending", "failed", "refunded"]),
        "invoice_id": f"in_{fake.uuid4()[:14]}",
        "subscription_id": f"sub_{fake.uuid4()[:14]}" if fake.boolean() else None,
        "metadata": {
            "plan": fake.random_element(["free", "basic", "premium", "enterprise"]),
            "user_id": fake.uuid4(),
            "feature_flags": ["feature_a", "feature_b"]
        },
        "billing_address": {
            "line1": fake.street_address(),
            "city": fake.city(),
            "state": fake.state_abbr(),
            "postal_code": fake.postcode(),
            "country": fake.country_code()
        },
        "created": fake.unix_time(),
        "receipt_url": fake.url()
    }


@pytest.fixture
def mock_jwt_token(app):
    """Enhanced JWT token fixture with different user roles"""
    def _create_token(identity_data=None):
        if identity_data is None:
            identity_data = {
                "id": fake.uuid4(),
                "email": "test@example.com",
                "role": "user",
                "plan": "free",
                "permissions": ["read"],
                "is_active": True
            }
        
        with app.app_context():
            return create_access_token(identity=identity_data)
    
    return _create_token


@pytest.fixture
def admin_token(mock_jwt_token):
    """JWT token for admin user"""
    return mock_jwt_token({
        "id": "admin_123",
        "email": "admin@test.com",
        "role": "admin",
        "plan": "enterprise",
        "permissions": ["read", "write", "delete", "admin"],
        "is_active": True
    })


@pytest.fixture
def user_token(mock_jwt_token):
    """JWT token for regular user"""
    return mock_jwt_token({
        "id": "user_456",
        "email": "user@test.com",
        "role": "user",
        "plan": "premium",
        "permissions": ["read", "write"],
        "is_active": True
    })


@pytest.fixture
def authenticated_headers(mock_jwt_token):
    """Enhanced authenticated headers with different token types"""
    def _get_headers(token_type="user", custom_token=None):
        if custom_token:
            token = custom_token
        elif token_type == "admin":
            with app.app_context():
                token = create_access_token(identity={
                    "id": "admin_123",
                    "email": "admin@test.com",
                    "role": "admin"
                })
        else:
            token = mock_jwt_token()
        
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Request-ID": fake.uuid4(),
            "User-Agent": "TestSuite/1.0"
        }
    
    return _get_headers


@pytest.fixture
def mock_stripe_customer():
    """Enhanced mock Stripe customer"""
    return {
        "id": f"cus_{fake.uuid4()[:14]}",
        "object": "customer",
        "email": fake.email(),
        "name": fake.name(),
        "phone": fake.phone_number(),
        "balance": 0,
        "created": fake.unix_time(),
        "currency": "usd",
        "default_source": f"card_{fake.uuid4()[:14]}",
        "delinquent": False,
        "description": f"Customer for {fake.email()}",
        "discount": None,
        "invoice_prefix": "INV",
        "invoice_settings": {
            "default_payment_method": None,
            "custom_fields": None,
            "footer": None
        },
        "livemode": False,
        "metadata": {
            "user_id": fake.uuid4(),
            "signup_source": "web"
        },
        "next_invoice_sequence": 1,
        "preferred_locales": ["en-US"],
        "shipping": {
            "address": {
                "city": fake.city(),
                "country": "US",
                "line1": fake.street_address(),
                "line2": None,
                "postal_code": fake.postcode(),
                "state": fake.state_abbr()
            },
            "name": fake.name(),
            "phone": fake.phone_number()
        },
        "tax_exempt": "none",
        "test_clock": None
    }


@pytest.fixture
def mock_stripe_payment_intent():
    """Enhanced mock Stripe payment intent"""
    return {
        "id": f"pi_{fake.uuid4()[:14]}",
        "object": "payment_intent",
        "amount": fake.random_int(min=1000, max=100000),
        "amount_capturable": 0,
        "amount_received": fake.random_int(min=1000, max=100000),
        "application": None,
        "application_fee_amount": None,
        "automatic_payment_methods": None,
        "canceled_at": None,
        "cancellation_reason": None,
        "capture_method": "automatic",
        "client_secret": f"pi_{fake.uuid4()[:14]}_secret_{fake.uuid4()[:8]}",
        "confirmation_method": "automatic",
        "created": fake.unix_time(),
        "currency": "usd",
        "customer": f"cus_{fake.uuid4()[:14]}",
        "description": fake.sentence(),
        "invoice": None,
        "last_payment_error": None,
        "livemode": False,
        "metadata": {
            "order_id": fake.uuid4(),
            "user_id": fake.uuid4()
        },
        "next_action": None,
        "on_behalf_of": None,
        "payment_method": f"pm_{fake.uuid4()[:14]}",
        "payment_method_options": {
            "card": {
                "installments": None,
                "mandate_options": None,
                "network": None,
                "request_three_d_secure": "automatic"
            }
        },
        "payment_method_types": ["card"],
        "processing": None,
        "receipt_email": fake.email(),
        "review": None,
        "setup_future_usage": None,
        "shipping": None,
        "source": None,
        "statement_descriptor": "EXAMPLE.COM",
        "statement_descriptor_suffix": None,
        "status": fake.random_element(["succeeded", "processing", "requires_payment_method"]),
        "transfer_data": None,
        "transfer_group": None
    }


@pytest.fixture
def mock_db_connection():
    """Enhanced mock database connection with query logging"""
    mock_conn = Mock()
    mock_cursor = Mock()
    query_log = []
    
    def execute_query(query, params=None):
        query_log.append({
            'query': query,
            'params': params,
            'timestamp': datetime.now().isoformat()
        })
        print(f"DB Query: {query[:100]}...")  # Log first 100 chars
        
        # Return mock results based on query type
        if 'SELECT' in query.upper():
            return [{'id': 1, 'name': 'Test Record'}]
        elif 'INSERT' in query.upper():
            return 1
        elif 'UPDATE' in query.upper():
            return 1
        elif 'DELETE' in query.upper():
            return 1
        return []
    
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.__enter__ = Mock(return_value=mock_cursor)
    mock_cursor.__exit__ = Mock(return_value=None)
    mock_cursor.execute = Mock(side_effect=execute_query)
    mock_cursor.fetchall = Mock(return_value=[{'id': 1, 'name': 'Test Record'}])
    mock_cursor.fetchone = Mock(return_value={'id': 1, 'name': 'Test Record'})
    mock_cursor.rowcount = 1
    
    # Add query log to connection for inspection
    mock_conn.query_log = query_log
    
    return mock_conn


@pytest.fixture
def mock_email_service():
    """Enhanced mock email service with send tracking"""
    email_log = []
    
    class MockEmailService:
        def __init__(self):
            self.sent_emails = []
            
        def send(self, to, subject, body, template=None, **kwargs):
            email_data = {
                'to': to,
                'subject': subject,
                'body': body[:100] + '...' if len(body) > 100 else body,
                'template': template,
                'timestamp': datetime.now().isoformat(),
                'kwargs': kwargs
            }
            self.sent_emails.append(email_data)
            email_log.append(email_data)
            print(f"Email sent to {to}: {subject}")
            return {'message_id': fake.uuid4(), 'status': 'sent'}
        
        def send_bulk(self, emails):
            results = []
            for email in emails:
                results.append(self.send(**email))
            return results
        
        def get_sent_count(self):
            return len(self.sent_emails)
        
        def clear_log(self):
            self.sent_emails.clear()
            email_log.clear()
    
    with patch('services.email.EmailService', return_value=MockEmailService()) as mock_service:
        yield mock_service.return_value


@pytest.fixture
def mock_cache():
    """Enhanced mock cache with TTL support and statistics"""
    cache = {}
    stats = {
        'hits': 0,
        'misses': 0,
        'sets': 0,
        'deletes': 0
    }
    
    class MockCache:
        def set(self, key, value, ttl=None):
            expires = datetime.now() + timedelta(seconds=ttl) if ttl else None
            cache[key] = {
                'value': value,
                'expires': expires,
                'created': datetime.now()
            }
            stats['sets'] += 1
            return True
        
        def get(self, key, default=None):
            item = cache.get(key)
            if item:
                if item['expires'] is None or item['expires'] > datetime.now():
                    stats['hits'] += 1
                    return item['value']
                else:
                    # Expired, remove it
                    del cache[key]
            
            stats['misses'] += 1
            return default
        
        def delete(self, key):
            if key in cache:
                del cache[key]
                stats['deletes'] += 1
                return True
            return False
        
        def clear(self):
            cache.clear()
            stats.update({'hits': 0, 'misses': 0, 'sets': 0, 'deletes': 0})
        
        def exists(self, key):
            return key in cache and (
                cache[key]['expires'] is None or 
                cache[key]['expires'] > datetime.now()
            )
        
        def keys(self, pattern="*"):
            # Simple pattern matching (supports * wildcard)
            import fnmatch
            return [k for k in cache.keys() if fnmatch.fnmatch(k, pattern)]
        
        def get_stats(self):
            return stats.copy()
        
        def get_info(self):
            return {
                'size': len(cache),
                'stats': stats.copy(),
                'keys': list(cache.keys())
            }
    
    return MockCache()


@pytest.fixture
def mock_stripe_service():
    """Comprehensive mock Stripe service"""
    with patch('stripe.Customer.create') as mock_customer_create, \
         patch('stripe.PaymentIntent.create') as mock_payment_intent_create, \
         patch('stripe.Subscription.create') as mock_subscription_create, \
         patch('stripe.Charge.retrieve') as mock_charge_retrieve:
        
        # Setup mock responses
        mock_customer_create.return_value = Mock(
            id='cus_mock123',
            email='customer@example.com',
            to_dict=lambda: {'id': 'cus_mock123', 'email': 'customer@example.com'}
        )
        
        mock_payment_intent_create.return_value = Mock(
            id='pi_mock123',
            client_secret='pi_mock123_secret_abc',
            status='succeeded',
            to_dict=lambda: {
                'id': 'pi_mock123',
                'client_secret': 'pi_mock123_secret_abc',
                'status': 'succeeded'
            }
        )
        
        mock_subscription_create.return_value = Mock(
            id='sub_mock123',
            status='active',
            current_period_end=datetime.now().timestamp() + 2592000,  # 30 days
            to_dict=lambda: {
                'id': 'sub_mock123',
                'status': 'active',
                'current_period_end': datetime.now().timestamp() + 2592000
            }
        )
        
        mock_charge_retrieve.return_value = Mock(
            id='ch_mock123',
            status='succeeded',
            receipt_url='https://receipt.example.com/ch_mock123',
            to_dict=lambda: {
                'id': 'ch_mock123',
                'status': 'succeeded',
                'receipt_url': 'https://receipt.example.com/ch_mock123'
            }
        )
        
        yield {
            'customer_create': mock_customer_create,
            'payment_intent_create': mock_payment_intent_create,
            'subscription_create': mock_subscription_create,
            'charge_retrieve': mock_charge_retrieve
        }


@pytest.fixture
def mock_async_service():
    """Mock async service for testing async functions"""
    async def async_mock_function(*args, **kwargs):
        await asyncio.sleep(0.01)  # Simulate async operation
        return {"status": "success", "data": kwargs.get("data", {})}
    
    return async_mock_function


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Enhanced setup and teardown for each test with environment isolation"""
    # Setup
    test_start = datetime.now()
    test_name = pytest.current_test_name if hasattr(pytest, 'current_test_name') else 'unknown'
    
    print(f"\n{'='*60}")
    print(f"Starting test: {test_name}")
    print(f"{'='*60}")
    
    # Set test environment variables
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TEST_MODE', 'true')
    
    # Mock external API calls to prevent real requests
    monkeypatch.setattr('requests.post', Mock(return_value=Mock(status_code=200, json=lambda: {})))
    monkeypatch.setattr('requests.get', Mock(return_value=Mock(status_code=200, json=lambda: {})))
    
    # Clear any previous test state
    if hasattr(pytest, 'test_context'):
        delattr(pytest, 'test_context')
    
    pytest.test_context = {
        'start_time': test_start,
        'name': test_name,
        'status': 'running'
    }
    
    yield
    
    # Teardown
    test_end = datetime.now()
    duration = (test_end - test_start).total_seconds()
    
    pytest.test_context['end_time'] = test_end
    pytest.test_context['duration'] = duration
    pytest.test_context['status'] = 'completed'
    
    print(f"\n{'='*60}")
    print(f"Finished test: {test_name}")
    print(f"Duration: {duration:.3f} seconds")
    print(f"{'='*60}\n")


@contextmanager
def assert_raises_with_message(exception_type, message_part):
    """Context manager to assert exception with specific message"""
    with pytest.raises(exception_type) as exc_info:
        yield exc_info
    
    assert message_part in str(exc_info.value), \
        f"Expected error message containing '{message_part}', got: {str(exc_info.value)}"


# Helper fixture for common assertions
@pytest.fixture
def assert_response():
    """Helper for asserting API responses"""
    def _assert_response(response, status_code=200, content_type='application/json'):
        assert response.status_code == status_code
        assert response.content_type == content_type
        
        if content_type == 'application/json':
            data = response.get_json()
            assert data is not None
            return data
        
        return response.data
    
    return _assert_response


# Custom pytest hook to get current test name
def pytest_runtest_protocol(item, nextitem):
    pytest.current_test_name = item.name
    pytest.current_test_module = item.module.__name__ if item.module else 'unknown'
    pytest.current_test_class = item.cls.__name__ if item.cls else 'unknown'


# Skip slow tests by default unless explicitly requested
def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)


# Command line options
def pytest_addoption(parser):
    parser.addoption(
        "--run-slow", action="store_true", default=False, help="run slow tests"
    )
    parser.addoption(
        "--integration", action="store_true", default=False, help="run integration tests"
    )
    parser.addoption(
        "--seed", action="store", default=None, help="seed for random data generation"
    )


# Global test data factory
@pytest.fixture
def factory_boy_factory():
    """Factory for creating test data using factory patterns"""
    class Factory:
        @staticmethod
        def create_user(**overrides):
            base = {
                'id': fake.uuid4(),
                'email': fake.email(),
                'username': fake.user_name(),
                'first_name': fake.first_name(),
                'last_name': fake.last_name(),
                'is_active': True,
                'role': 'user'
            }
            return {**base, **overrides}
        
        @staticmethod
        def create_lead(**overrides):
            base = {
                'id': fake.uuid4(),
                'name': fake.name(),
                'email': fake.email(),
                'company': fake.company(),
                'status': 'new'
            }
            return {**base, **overrides}
        
        @staticmethod
        def create_payment(**overrides):
            base = {
                'id': fake.uuid4(),
                'amount': fake.random_int(min=1000, max=10000),
                'currency': 'usd',
                'status': 'succeeded'
            }
            return {**base, **overrides}
    
    return Factory()