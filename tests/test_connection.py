"""Smoke test: verify Python can authenticate to AWS via the cloudguard profile."""
import pytest
from botocore.exceptions import ProfileNotFound

from src.aws_client import get_account_id, get_client


def test_can_connect_to_aws():
    """STS GetCallerIdentity should return a 12-digit account ID."""
    account_id = get_account_id()
    assert account_id is not None, "Account ID should not be None"
    assert len(account_id) == 12, f"Account ID should be 12 digits, got: {account_id}"
    assert account_id.isdigit(), f"Account ID should be all digits, got: {account_id}"
    print(f"\n✓ Connected to AWS account: {account_id}")


def test_sts_client_builds():
    """get_client should return a usable STS client."""
    sts = get_client("sts")
    assert sts is not None
    assert hasattr(sts, "get_caller_identity")


def test_profile_not_found_raises_gracefully():
    """A bogus profile should raise ProfileNotFound, not crash silently."""
    with pytest.raises(ProfileNotFound):
        get_client("sts", profile="profile-that-does-not-exist-xyz")