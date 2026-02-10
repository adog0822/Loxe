"""AWS STS cross-account role assumption for secure credential handling."""

import boto3
from botocore.exceptions import ClientError


def assume_role(
    role_arn: str,
    session_name: str = "EvidenceTracerAgent",
    region: str = "us-east-1",
    duration_seconds: int = 3600,
) -> dict[str, str]:
    """Assume an IAM role in another AWS account and return temporary credentials.

    The target account must have a trust policy that allows your account/role
    to call sts:AssumeRole on the target role ARN.

    Args:
        role_arn: Full ARN of the role to assume
                  (e.g. arn:aws:iam::123456789012:role/EvidenceTracerReadOnly).
        session_name: Human-readable name for the session (appears in CloudTrail).
        region: AWS region for the STS endpoint.
        duration_seconds: How long the temporary credentials are valid (max 3600).

    Returns:
        Dictionary with access_key_id, secret_access_key, session_token,
        expiration, assumed_role_arn, and region.

    Raises:
        RuntimeError: If the AssumeRole call fails.
    """
    sts = boto3.client("sts", region_name=region)

    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=duration_seconds,
        )
    except ClientError as exc:
        raise RuntimeError(
            f"Failed to assume role {role_arn}: {exc}"
        ) from exc

    creds = response["Credentials"]
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
        "expiration": creds["Expiration"].isoformat(),
        "assumed_role_arn": response["AssumedRoleUser"]["Arn"],
        "region": region,
    }


def create_session(role_arn: str, region: str = "us-east-1") -> boto3.Session:
    """Assume a role and return a boto3 Session with the temporary credentials.

    This is the main entry point for live-mode collection. The returned session
    can be passed to any collector that needs authenticated AWS access.
    """
    creds = assume_role(role_arn, region=region)
    return boto3.Session(
        aws_access_key_id=creds["aws_access_key_id"],
        aws_secret_access_key=creds["aws_secret_access_key"],
        aws_session_token=creds["aws_session_token"],
        region_name=region,
    )
