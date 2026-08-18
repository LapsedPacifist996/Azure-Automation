# SOC Runbook Automation Workflow

## Purpose

This document provides a logical step-by-step workflow for automating alert triage, notification, resolution, and documentation for an Anomalous Sign-In alert. This document is not comprehensive, and specific actions within the proposed automation would need to be compared against a specific tenant configuration and data to be implemented for production. 

## Design Plan

To automate this workflow, we make use of Microsoft Sentinel and Azure capabilities to build custom playbooks or Logic Apps that allow actions to be taken automatically on resources and users subsequent to an alert triggering. Actions taken and alert data requested from the Logic App are possible via "Connectors" between Microsoft platform APIs (e.g., Exchange, Teams, Graph, etc.) and to other Microsoft Graph API namespaces, including `microsoft.graph.security`.

A task in the SOC runbook can then be automated by a trigger event we know will happen (e.g., "an Incident/Alert is created or updated"), and an action taken, conditional on the data generated from that event. The design plan logic app with permissions justified by the runbook task requirements, then adding actions that update the incident, get further involved user data, and notify the user/IAM/IR when required.

## Tenant Configuration & Setup Requirements

- Microsoft Sentinel connected to Microsoft Defender Portal
- Global Administrator or Privileged Role Administrator to grant admin consent to app (for custom Azure Logic App consent grant)
- Microsoft Entra ID P2 License
- Microsoft Sentinel Playbook Creation and Management Pre-reqs

### Setup Steps

1. Register Logic App in tenant
2. Ensure necessary API permissions are granted admin consent:
   - `ThreatHunting.Read.All` — Run hunting queries for Now-30d
   - `RoleManagementAlert.ReadWrite.Directory` — Action alerts
   - `SecurityIncident.ReadWrite.All` — Update incidents
   - `AuditLog.Read.All` — Queries for incident disposition determination
   - `Directory.Read.All` — User data for investigation
   - `User.Read.All` — Sign-in metadata
   - `UserAuthenticationMethod.Read.All` — MFA and other authentication data
   - `Policy.Read.All` — Conditional Access review
   - `Mail.Read` — Mailbox investigation
   - `Mail.Send` — Outlook mail outreach to user (email user outreach)
   - `ChannelMessage.Send` — Teams message user outreach
3. Enable required connectors
4. Add app logic for triggers and actions
5. Test/Validate

## Workflow

```
[0] Sentinel Incident/Alert
    ↓ App Action(s):
        Initialize variables from incident for input to subsequent actions

[1] Acknowledge Incident & Extract Data (Logic App action)
    ↓ App Action(s):
        Change Incident status from "New" to "Active"
        Assign ownership to App
        Change Incident severity to "High"
        Get Related Entities, Incident Title, Description

[2-3] Check MFA + Conditional Access (parallel)
    ↓ App Action(s):
        Get/List User Authentication Methods

        Conditional:
        IF Non-Legacy MFA exists
            App Action(s): Notify user
                Send email/Teams message
            IF User recognizes location AND authorized activity
                App Action(s): Notify TDE, close alert as "Benign Positive"
                    Send email so detection can be updated with exclusion
        IF Legacy MFA or NO MFA:
            App Action(s): Notify user, escalate
                Send email/Teams message

        App Action(s): Get CAP values (success, failure, notApplied, notEnabled)

        Conditional:
        IF Conditional Access does not match expected
            App Action(s): Notify user, escalate
                Send email/Teams message

    [4] Query downstream (mailbox rules, file access, audit logs)
        ↓ App Action(s): Graph requests to relevant endpoints for user activity
            Mailbox rules request API endpoint example:
            GET https://graph.microsoft.com/v1.0/users/{userId}/mailFolders/inbox/messageRules

    [5] Manual review + Disposition decision
        ↓ App Action(s): Update incident

        Conditional:
        IF False Positive
            App Action(s): Mark incident as false positive
                Close incident
        IF Benign Positive
            App Action(s): Mark incident as benign positive
                Close incident
        IF True Positive
            App Action(s): Mark incident as true positive, escalate
                Block-AADUser or Block-AADUserOrAdmin where appropriate
                Send email to IAM/IR
                Reset password

[6] Close & Document (case notes)
    App Action(s): Update incident, close incident
```


## Permission mapping by investigation step

| Permission | Used for | Why it is needed in this workflow |
|---|---|---|
| `AuditLog.Read.All` | Audit and admin change review | Reads Microsoft 365 audit logs to detect suspicious admin changes, consent grants, role assignments, or account modifications |
| `Directory.Read.All` | User and directory metadata | Retrieves user properties, group membership, role or directory object details during investigation |
| `User.Read.All` | User account lookup | Reads account status, sign-in metadata, and profile details for the impacted identity |
| `UserAuthenticationMethod.Read.All` | MFA and auth method review | Checks whether MFA is enabled and whether authentication methods changed unexpectedly |
| `Policy.Read.All` | Conditional access review | Reads Entra policy and conditional access state to evaluate whether risky sign-ins were blocked or challenged |
| `SecurityEvents.Read.All` | Security event correlation | Pulls security-related data supporting risk, sign-in, and suspicious activity context |
| `Mail.Read` | Mailbox investigation | Reads mailbox metadata, rules, forwarding settings, or suspicious mail activity to detect compromise |
| `Mail.Send` | Outbound user notification or alerting | Sends email to the user or security team if email-based outreach is used |
| `ChannelMessage.Send` | Teams notifications | Sends direct messages or incident notifications in Microsoft Teams |

### Practical example for this runbook

- `Mail.Read` is required when the workflow checks for:
  - inbox forwarding rules
  - suspicious inbox rule creation
  - mailbox delegate or permission changes
  - message activity or mailbox-level abuse indicators
- `Mail.Send` is required only if the logic app sends email notifications directly from the workflow.
- `ChannelMessage.Send` is required only if the workflow posts Teams messages as part of user outreach or escalation.

---
