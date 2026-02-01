from datetime import datetime, timezone

class SOC2ControlMapper:
    """Map evidence to SOC 2 controls"""

    CONTROLS = {
        'CC6.1': {
            'name': 'Logical Access',
            'description': 'Logical access to systems is controlled through identification and authentication.',
            'aws_services': ['IAM', 'Cognito', 'Directory Service'],
            'evidence_types': ['user_authentication', 'password_policies', 'mfa_status']
        },
        'CC6.3': {
            'name': 'Access Key Management',
            'description': 'Identification and authentication are required for system access.',
            'aws_services': ['IAM', 'Secrets Manager', 'KMS'],
            'evidence_types': ['access_keys', 'key_rotation', 'secret_management']
        },
        'CC6.7': {
            'name': 'Least Privilege',
            'description': 'Access rights are reviewed on a periodic basis.',
            'aws_services': ['IAM', 'Organizations'],
            'evidence_types': ['policy_attachments', 'permission_boundaries', 'service_control_policies']
        },
        'CC7.1': {
            'name': 'Infrastructure Changes',
            'description': 'Changes to infrastructure are authorized.',
            'aws_services': ['CloudFormation', 'CloudTrail', 'Config'],
            'evidence_types': ['change_records', 'deployment_logs', 'approval_workflows']
        },
        'CC7.2': {
            'name': 'Security Configuration',
            'description': 'Systems are configured properly.',
            'aws_services': ['Config', 'Security Hub', 'GuardDuty'],
            'evidence_types': ['configuration_snapshots', 'compliance_checks', 'security_findings']
        },
        'CC7.4': {
            'name': 'Monitoring & Logging',
            'description': 'System events are monitored and logged.',
            'aws_services': ['CloudTrail', 'CloudWatch', 'VPC Flow Logs'],
            'evidence_types': ['log_files', 'monitoring_alerts', 'event_patterns']
        },
        'CC8.1': {
            'name': 'Change Management',
            'description': 'Changes are authorized, tested, approved, and documented.',
            'aws_services': ['CloudTrail', 'CodePipeline', 'Systems Manager'],
            'evidence_types': ['change_approvals', 'test_results', 'rollback_procedures']
        },
        'CC8.2': {
            'name': 'Data Management',
            'description': 'Data is classified, retained, and disposed of properly.',
            'aws_services': ['S3', 'RDS', 'DynamoDB', 'Macie'],
            'evidence_types': ['data_classification', 'retention_policies', 'backup_schedules']
        }
    }

    @classmethod
    def map_evidence_to_controls(cls, evidence_type, evidence_data):
        """Map evidence to relevant SOC 2 controls"""
        relevant_controls = []

        for control_id, control_info in cls.CONTROLS.items():
            if evidence_type in control_info['evidence_types']:
                relevant_controls.append({
                    'control_id': control_id,
                    'control_name': control_info['name'],
                    'mapping_strength': cls._calculate_mapping_strength(evidence_type, evidence_data)
                })

        return relevant_controls

    @staticmethod
    def _calculate_mapping_strength(evidence_type, evidence_data):
        """Calculate how strongly evidence maps to control"""
        # Simple scoring logic - can be enhanced
        if evidence_type in ['mfa_status', 'access_keys']:
            return 'high'
        elif evidence_type in ['policy_attachments', 'configuration_snapshots']:
            return 'medium'
        else:
            return 'low'
