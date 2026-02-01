import boto3
from datetime import datetime, timezone
import json

class IAMEvidenceCollector:
    def __init__(self):
        self.iam_client = boto3.client('iam')

    def collect_user_evidence(self):
        """Collect IAM users and their access details"""
        evidence = {
            'users': [],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'control_mappings': ['CC6.1', 'CC6.3', 'CC6.7']
        }

        try:
            # Get IAM users
            users = self.iam_client.list_users()
            for user in users['Users']:
                user_details = {
                    'username': user['UserName'],
                    'created': user['CreateDate'].isoformat(),
                    'mfa_enabled': self._check_mfa(user['UserName']),
                    'access_keys': self._get_access_keys(user['UserName']),
                    'policies': self._get_user_policies(user['UserName'])
                }
                evidence['users'].append(user_details)

        except Exception as e:
            evidence['error'] = str(e)

        return evidence

    def _check_mfa(self, username):
        """Check if MFA is enabled for user"""
        try:
            mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
            return len(mfa_devices['MFADevices']) > 0
        except:
            return False

    def _get_access_keys(self, username):
        """Get access keys for user"""
        try:
            keys = self.iam_client.list_access_keys(UserName=username)
            return [
                {
                    'access_key_id': key['AccessKeyId'],
                    'created': key['CreateDate'].isoformat(),
                    'status': key['Status'],
                    'age_days': (datetime.now(timezone.utc) - key['CreateDate']).days
                }
                for key in keys['AccessKeyList']
            ]
        except:
            return []

    def _get_user_policies(self, username):
        """Get policies attached to user"""
        policies = []
        try:
            # Get inline policies
            inline = self.iam_client.list_user_policies(UserName=username)
            policies.extend([{'name': p, 'type': 'inline'} for p in inline['PolicyNames']])

            # Get attached policies
            attached = self.iam_client.list_attached_user_policies(UserName=username)
            policies.extend([
                {'name': p['PolicyName'], 'type': 'managed', 'arn': p['PolicyArn']}
                for p in attached['AttachedPolicies']
            ])
        except:
            pass

        return policies
