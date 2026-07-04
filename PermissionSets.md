Permission Sets

Developer group assignments:
    Dev account - DeveloperAccess permission set
    Prod account - No assignment
    Security account - No assignment

SecurityAnalyst group assignments:
    Dev account - SecurityAuditAccess
    Prod account - SecurityAuditAccess
    Security account - SecurityAnalystFullAccess

Administrator group assignments:
    All accounts - AdministratorAccess (with MFA enforcement)
    In this project, the Administrator Access functions as a break-glass procedure.

Auditor group assignments:
    All accounts - AuditorAccess (read-only)

Who has access to the production account?
    Developers intentionally have no standing access to the Production account. Prod changes will flow through an automated deployment pipeline operating under its own scoped IAM role. Human access to Prod is restricted to Security Analysts (read-only) and Administrators (break-glass only), reflecting principles of least-privelege and separation of duties.
    If something breaks in Prod, there is a tiered escalation:
        1. Devs investigate production issues using read-only access. This allows them to see logs, metrics and resource configs without making any changes.
        2. If a fix is urgent, it goes through an expedited pipeline run: automated, audited, but faster.
        3. If the system is completely down and the pipeline is broken then this is a break-glass scenario. A time-limited, monitored elevated access is granted, every action is logged, and a review takes place afterward.

Permission Set 1 - DeveloperAccess
    Custom Permission Set based on AWS Managed Policy: PowerUserAccess
    Session duration: 8 hours
    Inline deny policy:
    {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Sid": "DenyIAMWrite",
        "Effect": "Deny",
        "Action": [
            "iam:CreateUser",
            "iam:DeleteUser",
            "iam:AttachRolePolicy",
            "iam:DeleteRolePolicy",
            "iam:PutRolePolicy",
            "iam:CreatePolicy",
            "iam:DeletePolicy",
            "iam:CreateAccessKey",
            "iam:UpdateAccessKey"
        ],
        "Resource": "*"
        },
        {
        "Sid": "DenyBillingAndAccountManagement",
        "Effect": "Deny",
        "Action": [
            "aws-portal:*",
            "billing:*",
            "budgets:ModifyBudget",
            "account:CloseAccount",
            "account:PutAlternateContact",
            "organizations:Leave*",
            "organizations:Delete*"
        ],
        "Resource": "*"
        }
    ]
    }

    The billing and account denials are added here to prevent Devs from modifying billing settings or closing accounts, which could be an operational risk.

Permission Set 2 - SecurityAnalyst
    Custom permission set based on AWS Managed Policy: SecurityAudit
    Session duration: 4 hours
    Relay state: https://console.aws.amazon.com/cloudtrail/home

    Additional managed policies to attach:
    These add explicit read access to services that SecurityAudit covers partially but not completely:
        CloudTrail - already covered by SecurityAudit
        GuardDuty - already covered by SecurityAudit
        Config - AWS managed read access is included in SecurityAudit
    Inline deny policy added to explicitly enforce no write actions:
    {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Sid": "DenyAllWrite",
        "Effect": "Deny",
        "Action": [
            "cloudtrail:DeleteTrail",
            "cloudtrail:StopLogging",
            "cloudtrail:UpdateTrail",
            "guardduty:DeleteDetector",
            "guardduty:DisassociateFromMasterAccount",
            "config:DeleteConfigRule",
            "config:DeleteConfigurationRecorder",
            "config:StopConfigurationRecorder",
            "iam:*",
            "organizations:*"
        ],
        "Resource": "*"
        }
    ]
    }
    This explicitly protects security tooling from being disabled even by someone using these credentials, thus creating a defence in depth control.

Permission Set 3 — AdministratorAccess
    Predefined permission set
    Policy: AdministratorAccess
    Session duration: 2 hours — deliberately short to reduce risk

    MFA enforcement:
    In IAM Identity Center, MFA enforcement is configured at the Identity Center settings level rather than within the permission set

    Inline deny to protect organisational structure:
    {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Sid": "DenyOrganisationChanges",
        "Effect": "Deny",
        "Action": [
            "organizations:DeleteOrganization",
            "organizations:RemoveAccountFromOrganization",
            "organizations:LeaveOrganization"
        ],
        "Resource": "*"
        }
    ]
    }
    Even administrators cannot remove accounts from the organisation or dissolve the organisation: those actions should only come from the management account root user under controlled circumstances.

Permission Set 4 — AuditorAccess
    Custom permission set based on AWS Managed Policy: ReadOnlyAccess
    Session duration: 4 hours
    Relay state: https://console.aws.amazon.com/config/home

    ReadOnlyAccess grants a user read access to almost everything, including secrets, parameter store values and S3 contents. An auditor needs to be able to see that a secret exists, and who has access, but does not need to be able to read the secret itself. As such, an inline deny policy is added to restrict access to sensitive data even within read-only:
    {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Sid": "DenySecretsAndKeyAccess",
        "Effect": "Deny",
        "Action": [
            "secretsmanager:GetSecretValue",
            "ssm:GetParameter",
            "ssm:GetParameters",
            "ssm:GetParametersByPath",
            "kms:Decrypt",
            "s3:GetObject"
        ],
        "Resource": "*"
        }
    ]
    }
