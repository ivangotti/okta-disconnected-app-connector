# Okta Disconnected App Governance Connector

A modern governance connector that brings any application under **Okta Identity Governance (OIG)** control—no native integration required. Simply provide a CSV file and let the connector automatically create disconnected apps, provision users, manage entitlements, and keep everything in sync.

### What It Does

- **Creates the disconnected app** in Okta from your CSV filename
- **Creates custom attributes** dynamically from any CSV column structure
- **Maps attributes** automatically to Okta user profile fields (50+ variations supported)
- **Enables governance** by registering the app with Okta Identity Governance
- **Imports users** with full profile data and app assignment
- **Creates entitlements catalog** from `ent_*` columns with all values
- **Performs role mining** to discover common permission patterns
- **Creates bundles** automatically for discovered roles
- **Monitors CSV for changes** continuously in sync mode

> **Experimental Project**: This connector is provided as-is for demonstration and testing purposes. Use at your own risk. Always test in a non-production environment first.

## Why Disconnected Apps?

Disconnected applications in Okta Identity Governance allow you to:

- **Access Requests**: Users can request access to application entitlements through self-service
- **Access Reviews/Certifications**: Managers can periodically review and certify user access
- **Segregation of Duties (SoD)**: Define and enforce policies that prevent toxic access combinations
- **Audit & Compliance**: Track who has access to what, with full history

**Note**: The application does NOT need to have authentication (SAML/OIDC) configured. The app serves as a governance container for managing entitlements and access - actual authentication to the target system is handled separately.

## Prerequisites

- Node.js 18.x or higher
- An Okta account with API access
- Okta Identity Governance (OIG) license for entitlement features

## Quick Start

### 1. Create an API Token (1 minute)

1. **Okta Admin Console** → **Security** → **API** → **Tokens**
2. Click **Create Token** → Name it "CSV Connector" → **Create**
3. **Copy the token immediately** (shown only once)

### 2. Create Configuration File

Create `config.json` in the project directory:

```json
{
  "oktaDomain": "your-company.okta.com",
  "apiToken": "00abc123XYZ_your-ssws-token-here"
}
```

### 3. Run the Connector

```bash
# Install dependencies
npm install

# Run the application
npm start
```

**That's it!** The connector will automatically process your CSV files.

---

## Configuration Reference

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `oktaDomain` | Your Okta tenant domain | `"company.okta.com"` |
| `apiToken` | SSWS API Token | `"00abc123XYZ..."` |

### Optional Fields

| Field | Description | Example |
|-------|-------------|---------|
| `selectedCsvFile` | Pre-select CSV file (skip prompt) | `"MyApp.csv"` |
| `syncInterval` | Enable sync mode (minutes) | `5` |
| `roleMining` | Role mining configuration | See below |

### Full Configuration Example

```json
{
  "oktaDomain": "your-company.okta.com",
  "apiToken": "00abc123XYZ_your-ssws-token-here",
  "selectedCsvFile": "My Application.csv",
  "syncInterval": 5,
  "roleMining": {
    "enabled": true,
    "minUserThreshold": 2,
    "createBundles": true,
    "syncMode": "initial"
  }
}
```

### Role Mining Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable/disable role mining |
| `minUserThreshold` | `2` | Minimum users required per role |
| `createBundles` | `true` | Create bundles in Okta (`false` = report only) |
| `syncMode` | `"initial"` | When to run: `"initial"`, `"every"`, or `"manual"` |

---

## Connector Features

### Core Capabilities
- **Disconnected App Creation**: Automatically creates governance-enabled applications from CSV filenames
- **User Provisioning**: Creates, updates, and removes users based on CSV data
- **Entitlement Management**: Auto-creates entitlements from `ent_*` columns and grants them to users
- **Profile Mapping**: Intelligently maps 50+ CSV column variations to Okta user profile fields
- **Custom Attributes**: Dynamically creates app user schema attributes from any CSV structure

### Scheduled Sync & Change Detection
- **Continuous Monitoring**: Runs as an agent, periodically checking for CSV changes
- **Smart Change Detection**: Detects new users, removed users, and attribute/entitlement changes
- **Dynamic Entitlement Values**: Automatically creates new entitlement values when they appear in CSV
- **Colorized Output**: Beautiful terminal output with syntax-highlighted JSON and color-coded status

### Reliability & Performance
- **Rate Limit Handling**: Built-in retry logic with backoff for Okta API limits
- **Error Recovery**: Automatic retry on transient failures (401, 429 errors)
- **Interactive Reconfiguration**: Prompts to fix configuration issues without restarting

---

## CSV File Structure

The application dynamically processes any CSV file. Column names are automatically mapped to Okta fields.

### Example CSV

```csv
Username,firstName,lastName,email,department,ent_CostCenter,ent_UserRole,ent_Permissions
john.doe@example.com,John,Doe,john.doe@example.com,Engineering,CC100,"Admin,Developer","View,Edit,Delete"
jane.smith@example.com,Jane,Smith,jane.smith@example.com,Sales,CC200,Consultant,"View,Submit"
```

### Column Types

| Column Type | Description | Example |
|-------------|-------------|---------|
| **Username/Login** | User identifier (auto-detected) | `Username`, `login`, `email`, `user` |
| **User Profile** | Mapped to Okta profile fields | `firstName`, `last_name`, `department` |
| **Entitlements** | Columns prefixed with `ent_` | `ent_Role`, `ent_Permissions` |

### Supported Username Columns

The app automatically detects username from these column names (case-insensitive):
- `username`, `login`, `email`, `user`, `userid`, `user_id`, `mail`

### Supported Profile Mappings

CSV columns are automatically mapped to Okta fields:

| CSV Column Variations | Okta Field |
|----------------------|------------|
| `firstName`, `first_name`, `fname`, `givenname` | `firstName` |
| `lastName`, `last_name`, `lname`, `surname` | `lastName` |
| `email`, `mail` | `email` |
| `employeeId`, `employee_id`, `employeeNumber` | `employeeNumber` |
| `department`, `dept` | `department` |
| `title`, `jobTitle`, `job_title` | `title` |
| `phone`, `primaryPhone`, `phoneNumber` | `primaryPhone` |
| `mobile`, `mobilePhone`, `cellPhone` | `mobilePhone` |
| `manager`, `managerId` | `manager` |
| ... and 50+ more variations | |

---

## Processing Flow

The application executes a 9-step automated workflow:

```
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: Load Configuration                                         │
│  → Reads config.json or prompts for Okta credentials                │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 2: CSV File Discovery                                         │
│  → Scans directory for .csv files, prompts if multiple found        │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 3: Application Processing                                     │
│  → Creates disconnected app (or finds existing) using CSV filename  │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 4: Entitlement Management Configuration                       │
│  → Registers app with Okta Governance, enables entitlement mgmt     │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 5: Custom Attribute Management                                │
│  → Creates app user schema attributes from CSV columns              │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 6: Profile Attribute Mapping                                  │
│  → Maps CSV columns to Okta user profile fields automatically       │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 7: Entitlement Catalog & Creation                             │
│  → Parses ent_* columns, creates entitlements with all values       │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 8: User Provisioning                                          │
│  → Creates/updates users, assigns to app, grants entitlements       │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 9: Role Mining & Bundle Creation                              │
│  → Discovers role patterns, creates entitlement bundles             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Entitlement Management

### Fully Automatic - No Manual Setup Required

The application **automatically enables entitlement management** for your app in Okta Identity Governance. No manual intervention needed:

1. **Auto-registers** the app with Okta Governance via opt-in API
2. **Auto-creates** all entitlements from CSV `ent_*` columns
3. **Auto-grants** entitlements to each user based on their CSV values

Just run `npm start` and everything is configured automatically.

### How Entitlements Work

1. **CSV columns** prefixed with `ent_` become entitlement types
2. **Cell values** become entitlement values (comma-separated supported)
3. **Users** are granted entitlements based on their CSV row values

### Example

For this CSV row:
```csv
ent_CostCenter,ent_UserRole,ent_Permissions
CC100,"Admin,Developer","View,Edit"
```

The app creates:
- **CostCenter** entitlement with value `CC100`
- **UserRole** entitlement with values `Admin`, `Developer`
- **Permissions** entitlement with values `View`, `Edit`

And grants all of these to the user.

---

## Role Mining & Bundle Creation

The connector includes **automated role discovery** that analyzes CSV entitlement patterns and creates **Okta Governance bundles** for common permission combinations.

### How It Works

After provisioning users (Step 8), the connector automatically:

1. **Analyzes CSV Data**: Reads all user entitlement assignments from the CSV
2. **Discovers Patterns**: Groups users with identical permission combinations
3. **Generates Role Candidates**: Creates role definitions for groups meeting the minimum threshold
4. **Creates Bundles**: Automatically creates Okta Governance bundles via API
5. **Reports Statistics**: Shows coverage metrics and bundle details

### Example Output

```
🎯 STEP 9: Role Mining & Bundle Creation
══════════════════════════════════════════════════════════════════════
📄 Reading user entitlement data from CSV...
✓ Loaded 100 user records from CSV
✓ Found 100 users with entitlements

🔍 Analyzing role patterns...
✓ Found 15 unique permission combinations
✓ Discovered 5 role candidates

📊 Discovered Role Candidates:
1. Finance_Analyst_ViewRead - 25 users (25.0% coverage)
2. Finance_Manager_ApproveSubmit - 18 users (18.0% coverage)
3. HR_Recruiter_PostInterview - 15 users (15.0% coverage)
4. IT_Admin_ConfigureDeploy - 12 users (12.0% coverage)
5. Sales_Rep_View - 10 users (10.0% coverage)

🏗️ Creating Bundles in Okta Governance
✓ Created: Finance_Analyst_ViewRead
✓ Created: Finance_Manager_ApproveSubmit
✓ Created: HR_Recruiter_PostInterview
✓ Created: IT_Admin_ConfigureDeploy
✓ Created: Sales_Rep_View

✅ Role Mining Complete!
   Bundles Created: 5
   Users Covered: 80 (80.0%)
```

---

## Scheduled Sync Mode

The application supports **continuous sync mode** that keeps monitoring the CSV file for changes and automatically syncs with Okta.

### Enable Sync Mode

Add `syncInterval` to your `config.json`:

```json
{
  "oktaDomain": "your-company.okta.com",
  "apiToken": "00abc123XYZ_your-ssws-token-here",
  "syncInterval": 5
}
```

This will check for CSV changes every 5 minutes.

### What Sync Mode Detects & Handles

| Change Type | Action |
|-------------|--------|
| **New user in CSV** | Create user in Okta, assign to app, grant entitlements |
| **User removed from CSV** | Revoke entitlements, unassign from app |
| **User attributes changed** | Update app user profile |
| **User entitlements changed** | Revoke old grants, create new grants |
| **New entitlement value in CSV** | Automatically create the new value in Okta |

### Running as a Service

For production use, run the connector as a background service:

```bash
# Using nohup
nohup npm start > sync.log 2>&1 &

# Or using pm2
pm2 start index.js --name "okta-sync"
pm2 logs okta-sync
pm2 stop okta-sync
```

---

## Troubleshooting

### "No username/email column found"

The app couldn't find a username column. Ensure your CSV has one of:
`Username`, `login`, `email`, `user`, `userid`, `user_id`, `mail`

### "Authentication incomplete" Error

The app will automatically prompt you to enter an API token if credentials are missing or invalid. Follow the on-screen instructions.

### Rate Limiting (HTTP 429)

The app includes automatic rate limit handling:
- Pauses every 10 users
- Retries on 429 errors with 5-second delay

### Governance API 405 Errors

Some governance endpoints return 405 (Method Not Allowed). This is normal:
- The opt-in endpoint works
- Entitlement creation still works via the main endpoint

---

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/apps` | Search for existing apps |
| `POST /api/v1/apps` | Create disconnected application |
| `GET/POST /api/v1/meta/schemas/apps/{id}` | Manage app user schema |
| `GET/POST /api/v1/mappings` | Profile attribute mappings |
| `GET/POST /api/v1/users` | User management |
| `POST /api/v1/apps/{id}/users` | Assign users to app |
| `POST /api/v1/governance/resources/source/{id}/optIn` | Enable governance |
| `POST /governance/api/v1/entitlements` | Create entitlements |
| `POST /governance/api/v1/grants` | Grant entitlements to users |

---

## Security Notes

- `config.json` is gitignored - never commit credentials
- Passwords for new users are randomly generated (16 chars, mixed case + numbers + symbols)
- API tokens should be rotated regularly

## License

ISC

## Author

Ivan Gotti (ivangotti@gmail.com)
