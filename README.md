# CSV Agent - Okta Application Automation

A Node.js application that automates SAML 2.0 application creation, user provisioning, and **entitlement management** in Okta based on CSV files.

## Features

- **SAML App Creation**: Automatically creates SAML 2.0 applications from CSV filenames
- **Custom Attributes**: Creates app user schema attributes from CSV columns
- **Profile Mapping**: Intelligently maps CSV columns to Okta user profile fields
- **User Provisioning**: Creates/updates users and assigns them to applications
- **Entitlement Management**: Creates entitlements from `ent_*` columns and assigns them to users
- **Dynamic Processing**: Works with any CSV structure - no hardcoded column names

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

### Authentication Options

1. **Device Flow** (Recommended for users): Authenticate via browser
2. **Client Credentials**: For service-to-service with OAuth app
3. **SSWS Token**: Legacy API token (required for some governance APIs)

### Required OAuth Scopes

Grant these scopes to your OAuth application:

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
│  → Creates SAML 2.0 app (or finds existing) using CSV filename      │
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

## Example Output

```
======================================================================
  CSV Agent - Okta SAML Application Automation
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
├── CLAUDE.md          # AI assistant instructions
└── README.md          # This file
```

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/apps` | Search for existing apps |
| `POST /api/v1/apps` | Create SAML application |
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
