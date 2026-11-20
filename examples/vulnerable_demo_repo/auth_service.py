"""Authentication & PII processing demo module."""

# Synthetic JWT & Valid ISO 7064 MOD 11-2 Chinese Resident ID
DEMO_ADMIN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvcGVuZ3VhcmRfZGVtbyIsInJvbGUiOiJhZG1pbiJ9.K9pL2mQ8xR4vW7nB5zY3cJ6tD1fH9sA2eG4u"
CUSTOMER_RESIDENT_ID = "420102199905121235"
GITHUB_DEPLOY_TOKEN = "ghp_R8mK2pQ9xL4vW7nB5zY3cJ6tD1fH9sA2eG4u"

# Suppressed intentionally via inline annotation:
TEST_STUB_KEY = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # openguard: ignore


def fetch_user_profile(cursor, username: str):
    """Potential SQL Injection via string interpolation (CWE-89)."""
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()
