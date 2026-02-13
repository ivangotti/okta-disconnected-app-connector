# Okta Disconnected App Governance Connector

A modern governance connector that brings any application under **Okta Identity Governance (OIG)** control—no native integration required. Simply provide a CSV file and let the connector automatically create disconnected apps, provision users, manage entitlements, and keep everything in sync.

## Why Disconnected Apps?

Disconnected applications in Okta Identity Governance allow you to:

- **Access Requests**: Users can request access to application entitlements through self-service
- **Access Reviews/Certifications**: Managers can periodically review and certify user access
- **Segregation of Duties (SoD)**: Define and enforce policies that prevent toxic access combinations
- **Audit & Compliance**: Track who has access to what, with full history

**Note**: The application does NOT need to have authentication (SAML/OIDC) configured. The app serves as a governance container for managing entitlements and access - actual authentication to the target system is handled separately.

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
- **Verbose Sync Results**: Detailed reporting after each sync cycle

### Reliability & Performance
- **Token Auto-Refresh**: OAuth tokens automatically refresh before expiration
- **Rate Limit Handling**: Built-in retry logic with backoff for Okta API limits
- **Error Recovery**: Automatic retry on transient failures (401, 429 errors)

## Prerequisites

- Node.js 18.x or higher
- An Okta account with API access
- Okta Identity Governance (OIG) license for entitlement features

## Quick Start

```bash
# Install dependencies
npm install

# Run the application
npm start

# Development mode with auto-reload
npm run dev
```

## Configuration

On first run, the application prompts for Okta credentials and saves them to `config.json`.

### Configuration File (`config.json`)

The configuration file stores your Okta connection settings. It is automatically created on first run, or you can create it manually.

#### Example: OAuth with Client Credentials (Recommended)

```json
{
  "oktaDomain": "your-company.okta.com",
  "clientId": "0oa1234567890abcdef",
  "clientSecret": "your-client-secret-here",
  "selectedCsvFile": "My Application.csv"
}
```

#### Example: OAuth with Private Key JWT

```json
{
  "oktaDomain": "your-company.okta.com",
  "clientId": "0oa1234567890abcdef",
  "privateKeyPath": "./private-key.pem",
  "selectedCsvFile": "My Application.csv"
}
```

#### Example: Device Flow (Interactive)

```json
{
  "oktaDomain": "your-company.okta.com",
  "authFlow": "device",
  "clientId": "0oa1234567890abcdef",
  "selectedCsvFile": "My Application.csv"
}
```

#### Example: SSWS Token + OAuth (Hybrid)

Some governance APIs require SSWS tokens. You can configure both:

```json
{
  "oktaDomain": "your-company.okta.com",
  "clientId": "0oa1234567890abcdef",
  "clientSecret": "your-client-secret-here",
  "apiToken": "00abc123XYZ_your-ssws-token-here",
  "selectedCsvFile": "My Application.csv"
}
```

#### Example: With Sync Mode Enabled

```json
{
  "oktaDomain": "your-company.okta.com",
  "clientId": "0oa1234567890abcdef",
  "clientSecret": "your-client-secret-here",
  "apiToken": "00abc123XYZ_your-ssws-token-here",
  "selectedCsvFile": "My Application.csv",
  "syncInterval": 5
}
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `oktaDomain` | Yes | Your Okta tenant domain (e.g., `company.okta.com`) |
| `clientId` | Yes* | OAuth application Client ID |
| `clientSecret` | No | OAuth client secret (for client_credentials flow) |
| `privateKeyPath` | No | Path to private key PEM file (for private_key_jwt) |
| `authFlow` | No | Set to `"device"` for interactive browser auth, or `"client_credentials"` (default) |
| `apiToken` | No | SSWS API token (needed for some governance APIs) |
| `selectedCsvFile` | No | Remembers your CSV file selection between runs |
| `syncInterval` | No | Enable scheduled sync mode - interval in **minutes** (e.g., `5` = every 5 minutes) |

*Required unless using SSWS token only (legacy)

> **Note**: Copy `config.example.json` to `config.json` and fill in your values. The `config.json` file is gitignored to protect your credentials.

### Authentication Options

1. **Client Credentials** (Recommended for automation): Use `clientId` + `clientSecret`
2. **Private Key JWT** (Most secure): Use `clientId` + `privateKeyPath`
3. **Device Flow** (Interactive): Use `clientId` + `authFlow: "device"` - authenticates in browser
4. **SSWS Token** (Legacy): Use `apiToken` only - some governance APIs still require this

### Required OAuth Scopes

Grant these scopes to your OAuth application in Okta Admin Console:

```
okta.apps.manage, okta.apps.read
okta.users.manage, okta.users.read
okta.schemas.manage, okta.schemas.read
okta.profileMappings.manage, okta.profileMappings.read
okta.governance.accessCertifications.manage
okta.governance.accessRequests.manage
```

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

## Processing Flow

The application executes an 8-step workflow:

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
│  → Creates app user schema attributes from all CSV columns          │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 6: Profile Attribute Mapping                                  │
│  → Maps CSV columns to Okta user profile fields automatically       │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 7: Entitlement Catalog & Creation                             │
│  → Parses ent_* columns, creates entitlements with all values       │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 8: User Provisioning                                          │
│  → Creates/updates users, assigns to app, grants entitlements       │
└─────────────────────────────────────────────────────────────────────┘
```

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

### Entitlement Grant API Format

Grants are created using the Okta Governance API:

```json
{
  "grantType": "CUSTOM",
  "targetPrincipal": {
    "externalId": "<user-id>",
    "type": "OKTA_USER"
  },
  "actor": "ADMIN",
  "target": {
    "externalId": "<app-id>",
    "type": "APPLICATION"
  },
  "entitlements": [
    {
      "id": "<entitlement-id>",
      "values": [
        {
          "id": "<value-id>",
          "name": "Admin",
          "description": "Admin",
          "label": "Admin"
        }
      ]
    }
  ]
}
```

## Scheduled Sync Mode

The application supports **continuous sync mode** that keeps monitoring the CSV file for user or entitlement changes and automatically keeps everything in sync with Okta. The agent runs indefinitely, checking for changes at configurable intervals.

### Enable Sync Mode

Add `syncInterval` to your `config.json`:

```json
{
  "syncInterval": 5
}
```

This will check for CSV changes every 5 minutes.

### Key Features

- **Continuous Monitoring**: Agent keeps running and checking for changes automatically
- **Dynamic Entitlement Creation**: New entitlement values in CSV are automatically created in Okta
- **User Lifecycle Management**: Handles adds, updates, and removals seamlessly
- **Token Auto-Refresh**: OAuth tokens are automatically refreshed before expiration
- **Rate Limit Handling**: Built-in retry logic for Okta API rate limits
- **Verbose Results**: Detailed sync results after each cycle

### What Sync Mode Detects & Handles

| Change Type | Action |
|-------------|--------|
| **New user in CSV** | Create user in Okta, assign to app, grant entitlements |
| **User removed from CSV** | Revoke entitlements, unassign from app |
| **User attributes changed** | Update app user profile |
| **User entitlements changed** | Revoke old grants, create new grants |
| **New entitlement value in CSV** | Automatically create the new value in Okta, then assign to user |

### Dynamic Entitlement Value Creation

When a new entitlement value appears in the CSV that doesn't exist in Okta, the sync automatically:

1. Detects the new value (e.g., a new role "Super Admin" added to a user)
2. Creates the value in the existing entitlement in Okta
3. Grants the new entitlement value to the user

```
🔄 SYNC: Checking for changes...

   → Checking for new entitlement values...
   → New entitlement value detected: "Super Admin" for Permissions
     ✓ Created: Super Admin (ent3abc123xyz)
   ✓ Created 1 new entitlement value(s):
     • permissions: "Super Admin"
```

### Sync Results Output

After each sync cycle, detailed results are displayed:

```
──────────────────────────────────────────────────
📊 SYNC RESULTS [3:45:32 PM]
──────────────────────────────────────────────────
  Entitlements Created: 1
  Users Added:          2
  Users Updated:        5
  Users Removed:        1
  Total in Okta:        102
  Total in CSV:         103
──────────────────────────────────────────────────
```

### Full Sync Cycle Example

```
⏰ [3:45:32 PM] Running scheduled sync...

🔄 SYNC: Checking for changes...

   → Checking for new entitlement values...
   ✓ All entitlement values already exist
   → Fetching current users from Okta...
   ✓ Found 100 user(s) currently assigned to app
   ✓ CSV contains 102 user(s)

   📊 Changes detected:
     • New users to add: 2
     • Users to update: 100
     • Users to remove: 0

   ➕ Adding new users from CSV...
     → Adding newuser@example.com...
     ✓ newuser@example.com added with entitlements

   🔄 Checking for updates...
     → Updating john.doe@example.com (changed: ent_Permissions)...
     ✓ john.doe@example.com updated
     ✓ Updated 1 user(s), 1 entitlement grant(s)

   ──────────────────────────────────────────────────
   📊 SYNC RESULTS [3:45:45 PM]
   ──────────────────────────────────────────────────
     Entitlements Created: 0
     Users Added:          2
     Users Updated:        1
     Users Removed:        0
     Total in Okta:        102
     Total in CSV:         102
   ──────────────────────────────────────────────────

   Next sync in 5 minute(s)
```

### Running as a Service

For production use, run the connector as a background service:

```bash
# Using nohup
nohup npm start > sync.log 2>&1 &

# Or using pm2
pm2 start index.js --name "okta-sync"

# View logs
pm2 logs okta-sync

# Stop the service
pm2 stop okta-sync
```

### Token Auto-Refresh

The sync mode automatically handles OAuth token expiration:

- Tokens are refreshed 5 minutes before expiration
- If a 401 error occurs, the token is automatically refreshed and the request retried
- No manual intervention needed for long-running sync processes

## Example Output

```
======================================================================
  Okta Disconnected App Governance Connector
======================================================================

📋 STEP 1: Loading Configuration
   ✓ Configuration loaded successfully
   ✓ Connected to Okta tenant: your-tenant.okta.com

📂 STEP 2: CSV File Discovery
   ✓ Found 1 CSV file: My Application.csv

🔧 STEP 3: Application Processing
   ✓ Application created successfully!
     • App ID: 0oa1b2c3d4e5f6g7h8i9
     • Status: ACTIVE

🔐 STEP 4: Entitlement Management Configuration
   ✓ Entitlement management enabled successfully
   ✓ Governance resource ID: res1a2b3c4d5e6f7g8h9

🏷️  STEP 5: Custom Attribute Management
   ✓ Created 10 custom attributes

🔗 STEP 6: Profile Attribute Mapping
   ✓ Mapped 6 attributes to Okta user profile

📦 STEP 7: Entitlement Catalog & Creation
   ✓ Created 3 entitlements with 20 total values

👥 STEP 8: User Provisioning
   📊 User Provisioning Summary:
     • Total users in CSV: 100
     • Created: 0
     • Updated: 100
     • Assigned to app: 100
     • Governance grants created: 100

======================================================================
✅ Processing Complete!
======================================================================
```

## Project Structure

```
├── index.js           # Main application (1600+ lines)
├── config.js          # Configuration management
├── config.json        # Credentials storage (gitignored)
├── package.json       # Dependencies
└── README.md          # This file
```

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

## Troubleshooting

### "No username/email column found"

The app couldn't find a username column. Ensure your CSV has one of:
`Username`, `login`, `email`, `user`, `userid`, `user_id`, `mail`

### "Invalid entitlement id(s): []"

This occurs when CSV values don't match created entitlement values. The app now handles:
- Duplicate values (e.g., "Admin,Admin" → deduplicated)
- Case-insensitive matching

### Rate Limiting (HTTP 429)

The app includes automatic rate limit handling:
- Pauses every 10 users
- Retries on 429 errors with 5-second delay

### Governance API 405 Errors

Some governance endpoints return 405 (Method Not Allowed). This is normal:
- The opt-in endpoint works
- Some enable/disable endpoints may not be available
- Entitlement creation still works via the main endpoint

## Security Notes

- `config.json` is gitignored - never commit credentials
- Passwords for new users are randomly generated (16 chars, mixed case + numbers + symbols)
- API tokens should be rotated regularly
- Use OAuth with scoped permissions when possible

## License

ISC

## Author

Ivan Gotti (ivangotti@gmail.com)
