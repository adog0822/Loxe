"""SOC 2 Trust Services Criteria definitions for Common Criteria (CC) controls."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ControlDefinition:
    control_id: str
    title: str
    category: str
    description: str
    required_evidence: list[str]


# CC6 – Logical and Physical Access Controls
CC6_1 = ControlDefinition(
    control_id="CC6.1",
    title="Logical Access Security",
    category="Logical and Physical Access Controls",
    description=(
        "The entity implements logical access security software, infrastructure, "
        "and architectures over protected information assets to protect them from "
        "security events to meet the entity's objectives."
    ),
    required_evidence=[
        "user_inventory",
        "mfa_status",
        "password_policy",
        "access_key_rotation",
        "role_inventory",
        "policy_inventory",
    ],
)

CC6_3 = ControlDefinition(
    control_id="CC6.3",
    title="Role-Based Access and Least Privilege",
    category="Logical and Physical Access Controls",
    description=(
        "The entity authorizes, modifies, or removes access to data, software, "
        "functions, and other protected information assets based on roles, "
        "responsibilities, or the system design and changes, giving consideration "
        "to the concepts of least privilege and segregation of duties."
    ),
    required_evidence=[
        "user_inventory",
        "mfa_status",
        "access_key_rotation",
        "role_inventory",
    ],
)

CC6_7 = ControlDefinition(
    control_id="CC6.7",
    title="Restriction and Management of System Access",
    category="Logical and Physical Access Controls",
    description=(
        "The entity restricts the transmission, movement, and removal of information "
        "to authorized internal and external users and processes, and protects it "
        "during transmission, movement, or removal to meet the entity's objectives."
    ),
    required_evidence=[
        "trail_configuration",
        "logging_status",
        "security_events",
    ],
)

# CC7 – System Operations
CC7_1 = ControlDefinition(
    control_id="CC7.1",
    title="Detection and Monitoring",
    category="System Operations",
    description=(
        "To meet its objectives, the entity uses detection and monitoring procedures "
        "to identify changes to configurations that result in the introduction of new "
        "vulnerabilities, and susceptibilities to newly discovered vulnerabilities."
    ),
    required_evidence=[
        "trail_configuration",
        "logging_status",
        "detector_status",
        "findings_summary",
    ],
)

CC7_2 = ControlDefinition(
    control_id="CC7.2",
    title="Anomaly Detection in Operations",
    category="System Operations",
    description=(
        "The entity monitors system components and the operation of those components "
        "for anomalies that are indicative of malicious acts, natural disasters, and "
        "errors affecting the entity's ability to meet its objectives."
    ),
    required_evidence=[
        "trail_configuration",
        "logging_status",
        "security_events",
        "detector_status",
        "findings_summary",
    ],
)

CC7_4 = ControlDefinition(
    control_id="CC7.4",
    title="Incident Response",
    category="System Operations",
    description=(
        "The entity responds to identified security incidents by executing a defined "
        "incident response program to understand, contain, remediate, and communicate "
        "security incidents."
    ),
    required_evidence=[
        "logging_status",
        "security_events",
        "findings_summary",
    ],
)

# CC8 – Change Management
CC8_1 = ControlDefinition(
    control_id="CC8.1",
    title="Change Management Process",
    category="Change Management",
    description=(
        "The entity authorizes, designs, develops or acquires, configures, documents, "
        "tests, approves, and implements changes to infrastructure, data, software, "
        "and procedures to meet its objectives."
    ),
    required_evidence=[
        "trail_configuration",
        "logging_status",
        "security_events",
    ],
)

CC8_2 = ControlDefinition(
    control_id="CC8.2",
    title="Infrastructure and Software Testing",
    category="Change Management",
    description=(
        "The entity tests infrastructure and software changes in a separate environment "
        "prior to production deployment."
    ),
    required_evidence=[
        "trail_configuration",
        "security_events",
    ],
)

ALL_CONTROLS: dict[str, ControlDefinition] = {
    c.control_id: c
    for c in [CC6_1, CC6_3, CC6_7, CC7_1, CC7_2, CC7_4, CC8_1, CC8_2]
}
