"""Auth0 authentication handler for the Streamlit dashboard."""

import os
from typing import Any
from urllib.parse import urlencode

import requests
import streamlit as st


class Auth0Handler:
    """Wraps the Auth0 Authorization Code flow for Streamlit apps.

    Required env vars (set these before running the dashboard):
      AUTH0_DOMAIN       – e.g. my-tenant.us.auth0.com
      AUTH0_CLIENT_ID    – Application Client ID
      AUTH0_CLIENT_SECRET – Application Client Secret
      AUTH0_CALLBACK_URL – Must match the Allowed Callback URL in Auth0
                           (defaults to http://localhost:8501)
    """

    def __init__(self) -> None:
        self.domain = os.environ.get("AUTH0_DOMAIN", "")
        self.client_id = os.environ.get("AUTH0_CLIENT_ID", "")
        self.client_secret = os.environ.get("AUTH0_CLIENT_SECRET", "")
        self.callback_url = os.environ.get(
            "AUTH0_CALLBACK_URL", "http://localhost:8501"
        )

    @property
    def is_configured(self) -> bool:
        """Return True when all required Auth0 settings are present."""
        return bool(self.domain and self.client_id and self.client_secret)

    def get_login_url(self) -> str:
        """Build the Auth0 /authorize redirect URL."""
        params = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.callback_url,
                "scope": "openid profile email",
            }
        )
        return f"https://{self.domain}/authorize?{params}"

    def exchange_code(self, code: str) -> dict[str, Any] | None:
        """Exchange an authorization code for tokens."""
        resp = requests.post(
            f"https://{self.domain}/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": self.callback_url,
            },
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        return resp.json()

    def get_user_info(self, access_token: str) -> dict[str, Any] | None:
        """Fetch the authenticated user's profile from Auth0."""
        resp = requests.get(
            f"https://{self.domain}/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        return resp.json()

    def check_auth(self) -> dict[str, Any] | None:
        """Check if the current Streamlit session is authenticated.

        Returns user info dict if authenticated, None otherwise.
        Handles the OAuth2 callback automatically.
        """
        # Already authenticated in this session
        if "user" in st.session_state:
            return st.session_state["user"]

        if not self.is_configured:
            return None

        # Check for the OAuth callback code in query params
        code = st.query_params.get("code")
        if not code:
            return None

        tokens = self.exchange_code(code)
        if not tokens or "access_token" not in tokens:
            return None

        user = self.get_user_info(tokens["access_token"])
        if user:
            st.session_state["user"] = user
            st.query_params.clear()
            st.rerun()

        return None

    def logout(self) -> None:
        """Clear the session and redirect to Auth0 logout."""
        st.session_state.pop("user", None)
        st.session_state.pop("results", None)
        st.session_state.pop("ai_analysis", None)
        st.session_state.pop("evidence", None)
