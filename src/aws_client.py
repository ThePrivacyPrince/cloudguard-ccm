"""AWS client factory for CloudGuard.

Provides boto3 session and client objects using named AWS profiles.
Never hardcodes credentials — relies on ~/.aws/credentials for secret storage.
"""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


DEFAULT_PROFILE = "cloudguard"
DEFAULT_REGION = "us-east-1"


def get_session(profile: str = DEFAULT_PROFILE, region: str = DEFAULT_REGION):
    """Return a boto3 Session using a named profile.

    Credentials are read from ~/.aws/credentials — never passed as arguments.
    """
    return boto3.Session(profile_name=profile, region_name=region)


def get_client(service: str, profile: str = DEFAULT_PROFILE, region: str = DEFAULT_REGION):
    """Return a boto3 client for a given AWS service.

    Args:
        service: AWS service name, e.g. 'iam', 's3', 'sts', 'cloudtrail'
        profile: Named profile from ~/.aws/credentials
        region:  AWS region

    Returns:
        boto3 low-level client for the requested service
    """
    session = get_session(profile=profile, region=region)
    return session.client(service)


def get_account_id(profile: str = DEFAULT_PROFILE) -> str:
    """Return the 12-digit AWS account ID for sanity-checking connectivity.

    Calls STS GetCallerIdentity — a free, read-only API call that works
    for any authenticated principal regardless of additional permissions.
    """
    sts = get_client("sts", profile=profile)
    identity = sts.get_caller_identity()
    return identity["Account"]