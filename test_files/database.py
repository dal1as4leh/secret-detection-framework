# Database configuration file
# WARNING: This file contains demo secrets for research purposes only

import os

# Hardcoded credentials (BAD PRACTICE - for testing only)
DATABASE_HOST = "prod-db.company.com"
DATABASE_USER = "admin"
DATABASE_PASSWORD = "SuperSecret123!"
DATABASE_NAME = "production_db"

# AWS credentials (BAD PRACTICE - for testing only)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"

# GitHub Token (BAD PRACTICE - for testing only)
GITHUB_TOKEN = "ghp_EXAMPLE1234567890abcdefghijklmnop"

# Stripe Payment Key (BAD PRACTICE - for testing only)
STRIPE_SECRET_KEY = "sk_live_EXAMPLE1234567890abcdefgh"

# The CORRECT way to handle secrets
def get_db_connection():
    # Should use environment variables instead
    password = os.environ.get("DB_PASSWORD")
    return password
