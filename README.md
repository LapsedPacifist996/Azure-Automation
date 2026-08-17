# Azure Logic App Runbook Setup for Sentinel User Risk Investigation

## Objective
Automate the full Microsoft Sentinel investigation workflow for suspicious user sign-ins and account compromise indicators using Azure Logic Apps, with Microsoft Graph, Entra ID, Sentinel, Teams/Outlook, and audit connectors.

---

## Recommended Azure design

Use a single Logic App workflow with conditional branches and approval gates.

Primary trigger:
- Microsoft Sentinel connector: when an incident or alert is generated

Key connectors:
- Microsoft Sentinel
- Microsoft Entra ID / Microsoft Graph
- Office 365 Outlook
- Microsoft Teams
- Azure Monitor / Log Analytics (optional for CA and log correlation)
- Azure Key Vault (optional for secret storage)

Recommended hosting:
- Logic App Standard (preferred) for better operational control, managed identity, and deployment repeatability

---

## Prerequisites

1. Azure subscription with access to:
   - Microsoft Sentinel workspace
   - Log Analytics workspace
   - Azure resource group
   - Logic App Standard or Consumption service

2. Permissions:
   - Sentinel contributor/responder access
   - Microsoft Entra ID Global Reader or higher for sign-in review
   - Security Reader / Security Admin for investigation context
   - Graph permissions for sign-in and audit data access
   - Exchange and Teams access for user notification

3. Required app permissions or managed identity:
   - `AuditLog.Read.All`
   - `Directory.Read.All`
   - `User.Read.All`
   - `UserAuthenticationMethod.Read.All`
   - `Policy.Read.All`
   - `SecurityEvents.Read.All`
   - `Mail.Read`
   - `Mail.Send` if using Outlook automation
   - `ChannelMessage.Send` for Teams outbound messaging

---

## Extract the ARM resource ID from the Defender incident URL

Use a small expression-based parsing flow in the Logic App instead of trying to extract the value manually from the full string. The key is to split the URL at the `?id=` marker and then strip any trailing query parameters.

### 1. Initialize the raw URL

Add an action:
- `Initialize variable`
- Name: `IncidentUrl`
- Type: `String`
- Value:

```text
triggerBody()?['properties']?['incidentUrl']
```

If the trigger payload uses a different field name, substitute the correct source such as:

```text
triggerBody()?['url']
```

### 2. Extract the segment after the `id=` query parameter

Add a `Compose` action named `GetArmIdSegment` with this expression:

```text
if(
  contains(variables('IncidentUrl'), '?id='),
  substring(variables('IncidentUrl'), add(indexOf(variables('IncidentUrl'), '?id='), 4)),
  null
)
```

This trims the URL down to everything after `?id=`.

### 3. Remove trailing query params

Add a `Set variable` action named `ArmResourceId` with:

```text
if(
  contains(outputs('GetArmIdSegment'), '&'),
  first(split(outputs('GetArmIdSegment'), '&')),
  outputs('GetArmIdSegment')
)
```

This removes any trailing values such as `&viewid=...` and leaves only the ARM resource ID.

### 4. Decode URL-encoded characters

If the ID is URL-encoded, add a final variable:

```text
uriComponentToString(variables('ArmResourceId'))
```

This converts values like `%2Fsubscriptions%2F` back to `/subscriptions/`.

### Example

Input URL:

```text
https://security.microsoft.com/incident/123456?viewid=alerts&id=/subscriptions/11111111-2222-3333-4444-555555666666/resourceGroups/rg-prod/providers/Microsoft.Security/locations/westus/alerts/abcdef123456
```

After the expression chain, the output becomes:

```text
/subscriptions/11111111-2222-3333-4444-555555666666/resourceGroups/rg-prod/providers/Microsoft.Security/locations/westus/alerts/abcdef123456
```

### Fallback pattern for encoded URLs

If the portal sends the ID in an encoded format without a normal `?id=` query parameter, use this fallback:

```text
if(
  contains(variables('IncidentUrl'), '%2Fsubscriptions%2F'),
  uriComponentToString(variables('IncidentUrl')),
  null
)
```

This is useful when the URL has been normalized or passed through an intermediary service before the workflow.

---

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

## Azure setup steps

### 1. Create the Azure resource group

In Azure Portal:
1. Search for Resource Groups
2. Click Create
3. Set name, region, tags
4. Save

### 2. Create the Logic App Standard

1. Search for Logic App (Standard)
2. Click Create
3. Select the new resource group
4. Choose region close to the Sentinel workspace
5. Set app name and plan
6. Review and create

### 3. Enable managed identity

1. Open the Logic App
2. Navigate to Identity
3. Set System assigned to On
4. Save
5. Note the object ID for role assignment

### 4. Assign Azure RBAC roles to the Logic App managed identity

Grant access for investigation actions:
- Reader on Log Analytics workspace
- Sentinel Responder or Sentinel Contributor on the workspace
- Security Reader on the subscription or workspace
- Microsoft Entra role assignment to query sign-ins and conditional access data (via Graph/API permissions or app registration)

### 5. Create an app registration for Graph access (if not using managed identity directly)

1. Azure Portal > Microsoft Entra ID > App registrations > New registration
2. Name it `Sentinel-IR-LogicApp`
3. Use single tenant
4. Create and note Application ID and Directory ID
5. Add API permissions:
   - Microsoft Graph: AuditLog.Read.All
   - Microsoft Graph: Directory.Read.All
   - Microsoft Graph: Policy.Read.All
   - Microsoft Graph: User.Read.All
   - Microsoft Graph: UserAuthenticationMethod.Read.All
   - Microsoft Graph: SecurityEvents.Read.All
6. Grant admin consent
7. Store secret in Key Vault if needed

### 6. Create the workflow in Logic Apps Designer

Create a workflow named:
- `Sentinel-UserRisk-Investigation`

Set trigger:
- When an incident is created or updated

### 7. Add workflow variables

Initialize variables:
- `AlertId`
- `IncidentId`
- `UserPrincipalName`
- `AccountName`
- `SourceIP`
- `SourceLocation`
- `AlertTimestamp`
- `Disposition`
- `ContainmentRequired`
- `InvestigationStatus`

### 8. Add actions for alert acknowledgement

Action:
- Update incident in Microsoft Sentinel

Example settings:
- Status: In Progress
- Severity: unchanged
- Add notes:
  - User principal name
  - Source IP
  - Source location
  - Alert timestamp
  - Analyst: Automation

### 10. Query recent sign-ins for the user

Use Microsoft Graph SignIn logs or Log Analytics query:
- `SigninLogs`
- filter `UserPrincipalName` equal to the impacted account
- last 30 days

Relevant fields:
- TimeGenerated
- ResultType
- ResultDescription
- IPAddress
- LocationDetails
- AppDisplayName
- DeviceDetail
- ConditionalAccessStatus
- MFAResult
- RiskLevelAggregated

### 11. Assess suspicious behavior

Add conditional logic for suspicious sign-ins:
- new country or region
- impossible travel
- unfamiliar device or OS
- unusual time-of-day
- sign-in from suspicious IP/VPN/Proxy
- risk level above baseline
- failed MFA or repeated failures

Example logic:
- If sign-in is from same country and same device and same time pattern -> likely benign
- If sign-in is from new country or anonymizing IP -> suspicious

### 12. Check MFA status

Use Microsoft Graph or Entra auth methods retrieval.

Actions:
- retrieve `AuthenticationMethods` for the user
- check if MFA is enabled
- check recent MFA registration changes

Decision:
- MFA enabled + normal location = continue to user outreach
- MFA enabled + new country = continue to conditional access review
- MFA disabled = escalate for investigation and possible containment

### 13. Review conditional access policy evaluation

Query sign-in details for:
- `conditionalAccessStatus`
- `riskLevelAggregated`
- `resultType`
- `status`

Decision categories:
- Allowed
- Blocked
- Challenged
- Not evaluated

Record whether policy outcome aligns with expected behavior.

### 14. Notify the user via standard channel

Connectors:
- Microsoft Teams
- Office 365 Outlook

Use a notification message:
- user account activity from location and IP
- request confirmation if they recognize the activity
- include a response deadline and escalation path

If no response by SLA:
- escalate to IAM/security lead using Teams/Outlook/incident comments

### 15. Check downstream activity

Use Microsoft Graph / Audit logs to inspect:
- mailbox rule creation
- mail forwarding changes
- new inbox delegates
- file access anomalies
- SharePoint/OneDrive downloads
- admin role changes
- consent grants
- new app registration or OAuth permissions

Typical suspicious indicators:
- new inbox rule removing mail
- external forwarding configured
- large file downloads
- group membership changes
- role assignments

### 16. Determine disposition

Decision logic:
- `True Positive` if suspicious sign-in + user denies activity or no response + downstream malicious behavior
- `False Positive` if activity matches normal user pattern
- `Benign Positive` if user confirms legitimate access and no malicious actions occurred

Document:
- rationale
- evidence sources
- sign-in timeline
- user confirmation status
- downstream activity findings

### 17. Containment if disposition is True Positive

Actions:
- disable user account
- revoke active sessions
- reset user password
- block sign-ins or require re-registration
- notify IAM team
- open formal incident response process

Connectors:
- Microsoft Graph (user disable, password reset, revoke sessions)
- Microsoft Teams or email to IAM/security operations

### 18. Update the case and close

Final actions:
- add disposition summary to Sentinel incident
- mark closed or resolved
- attach summary notes and timeline
- notify stakeholders and Tier 2/Tier 3 analysts

---

## Required connectors and purpose

| Connector | Purpose |
|---|---|
| Microsoft Sentinel | Trigger and incident update |
| Microsoft Entra ID / Microsoft Graph | Sign-in history, MFA, CA, user info, account disable/reset |
| Azure Monitor / Log Analytics | Correlate sign-ins and risk events |
| Office 365 Outlook | User outreach and escalation email |
| Microsoft Teams | Real-time user confirmation and SOC escalation |
| Azure Key Vault | Store credentials and secrets securely |

---

## Suggested workflow logic summary

1. Trigger on Sentinel alert
2. Acknowledge the incident immediately
3. Pull last 30 days of sign-ins
4. Compare activity to baseline user behavior
5. Check suspicious indicators
6. Evaluate MFA and CA policy
7. Contact the user
8. Review downstream activity
9. Determine disposition
10. Contain if true positive
11. Document and close

---

## Recommended implementation pattern

This should be implemented as:
- One main Logic App workflow with nested conditions
- Manual analyst review gates before irreversible actions
- A final incident closure block with note capture

