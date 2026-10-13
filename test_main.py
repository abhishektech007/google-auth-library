#!/usr/bin/env python3
"""
=============================================================================
Unit Test Suite: test_main.py
Framework: pytest + fastapi.testclient.TestClient + unittest.mock
Purpose: Verifies Google OAuth 2.0 verification logic, JWT issuance, and RBAC
=============================================================================
"""

import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Configure test environment variables prior to importing application
os.environ["ENVIRONMENT"] = "test"
os.environ["GOOGLE_CLIENT_ID"] = "test-client-id-12345.apps.googleusercontent.com"
os.environ["JWT_SECRET"] = "test_super_secure_secret_key_with_at_least_32_characters_length"
os.environ["ALLOWED_ORIGIN"] = "http://localhost:4200"

from main import app, generate_session_token, UserProfile

client = TestClient(app)


# -----------------------------------------------------------------------------
# Test 1: Health Probe Verification
# -----------------------------------------------------------------------------
def test_health_probe():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["environment"] == "test"


# -----------------------------------------------------------------------------
# Test 2: Missing Token Payload Validation
# -----------------------------------------------------------------------------
def test_authenticate_google_missing_token():
    response = client.post("/api/auth/google", json={})
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert data["detail"]["code"] == "BAD_REQUEST"


# -----------------------------------------------------------------------------
# Test 3: Invalid Google ID Token Verification
# -----------------------------------------------------------------------------
@patch("main.id_token.verify_oauth2_token")
def test_authenticate_google_invalid_token(mock_verify):
    mock_verify.side_effect = ValueError("Token signature verification failed")

    response = client.post("/api/auth/google", json={"credential": "invalid.jwt.token"})
    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["code"] == "INVALID_GOOGLE_TOKEN"


# -----------------------------------------------------------------------------
# Test 4: Unverified Email Rejection (Security Check)
# -----------------------------------------------------------------------------
@patch("main.id_token.verify_oauth2_token")
def test_authenticate_google_unverified_email(mock_verify):
    mock_verify.return_value = {
        "iss": "https://accounts.google.com",
        "sub": "google-user-sub-123",
        "email": "unverified@gmail.com",
        "email_verified": False,
        "name": "Unverified User",
    }

    response = client.post("/api/auth/google", json={"credential": "sample.valid.token"})
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["code"] == "EMAIL_NOT_VERIFIED"


# -----------------------------------------------------------------------------
# Test 5: Successful Google ID Token Verification & Session JWT Issuance
# -----------------------------------------------------------------------------
@patch("main.id_token.verify_oauth2_token")
def test_authenticate_google_success(mock_verify):
    mock_verify.return_value = {
        "iss": "accounts.google.com",
        "sub": "109876543210987654321",
        "email": "architect@company.com",
        "email_verified": True,
        "name": "Jane Architect",
        "picture": "https://lh3.googleusercontent.com/avatar/jane.jpg",
        "given_name": "Jane",
        "family_name": "Architect",
    }

    response = client.post("/api/auth/google", json={"credential": "valid.google.idtoken"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "token" in data
    assert data["user"]["sub"] == "109876543210987654321"
    assert data["user"]["email"] == "architect@company.com"

    # Verify session cookie was set
    assert "session_token" in response.cookies


# -----------------------------------------------------------------------------
# Test 6: Protected Resource Authorization Check
# -----------------------------------------------------------------------------
def test_protected_resource_unauthorized():
    client.cookies.clear()
    response = client.get("/api/protected/resource")
    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["code"] == "UNAUTHORIZED"


def test_protected_resource_authorized():
    # Mint test session JWT
    test_user = UserProfile(
        sub="10987654321",
        email="developer@company.com",
        name="Test Developer",
        picture="",
    )
    session_token = generate_session_token(test_user)

    # Request with Bearer header
    headers = {"Authorization": f"Bearer {session_token}"}
    response = client.get("/api/protected/resource", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["authorizedUser"] == "developer@company.com"
    assert "Verified Google OAuth 2.0 Identity" in data["clearance"]
