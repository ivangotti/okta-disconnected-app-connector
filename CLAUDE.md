# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
npm install

# Run the application
npm start

# Development mode with auto-reload
npm run dev
```

## Architecture

This is a Node.js application using ES modules (`"type": "module"`) that automates SAML 2.0 application creation in Okta based on CSV filenames.

### Key Components

- **index.js**: Main entry point with core functions:
  - `findCsvFiles()`: Scans current directory for .csv files
  - `findAppByName(config, appName)`: Searches Okta for existing app by label using `/api/v1/apps?q=` endpoint
  - `createSamlApp(config, appName)`: Creates SAML 2.0 app using `/api/v1/apps` POST endpoint
  - `getCsvColumns(csvFilePath)`: Reads CSV file and extracts column headers, filtering out columns starting with "ent_"
  - `getAppUserSchema(config, appId)`: Retrieves current app user schema from Okta
  - `createCustomAttribute(config, appId, attributeName)`: Creates a single custom attribute in app user schema
  - `processCustomAttributes(config, appId, csvFilePath)`: Orchestrates custom attribute creation from CSV columns
  - `getOktaNativeAttributes()`: Returns mapping of common attribute name variations to Okta native fields
  - `findMatchingOktaAttribute(attributeName)`: Matches custom attribute names to Okta user profile attributes
  - `getProfileMapping(config, appId)`: Fetches app-to-user profile mapping configuration
  - `updateProfileMapping(config, mappingId, properties)`: Updates profile mapping with new attribute mappings
  - `processAttributeMappings(config, appId, attributes)`: Creates mappings from custom attributes to Okta user profile
  - `generateEntitlementCatalog(csvFilePath)`: Parses CSV to extract unique values from columns with `ent_` prefix
  - `getAppEntitlements(config, appId)`: Fetches existing entitlements from Okta Governance API (tries multiple endpoint patterns)
  - `processEntitlements(config, appId, csvFilePath)`: Generates entitlement catalog and checks against Okta Governance

- **config.js**: Configuration management module with four key functions:
  - `getConfig()`: Main entry point - returns config from file or prompts user
  - `loadConfig()`: Reads from config.json
  - `getConfigInteractively()`: Prompts user for oktaDomain and apiToken, saves to config.json
  - `selectCsvFile(csvFiles)`: Prompts user to select from multiple CSV files

### Application Flow

1. Initialize: Get config (from config.json or prompt user)
2. Discovery: Scan current directory for .csv files
3. CSV Selection:
   - If only 1 CSV file: Use it automatically
   - If multiple CSV files:
     - Check if `config.selectedCsvFile` exists and is valid
     - If yes: Use saved selection
     - If no: Prompt user to select, save choice to `config.selectedCsvFile`
4. Process selected CSV file:
   - Extract app name from filename (without .csv extension)
   - Query Okta API to check if app with that label exists
   - If exists: Display app ID and status
   - If not exists: Create SAML 2.0 app and display new app ID
5. Custom Attributes Processing:
   - Read CSV column headers
   - Filter out columns starting with "ent_"
   - Fetch existing app user schema from Okta
   - Create custom attributes for columns that don't already exist
   - Display results (created/skipped attributes)
6. Profile Attribute Mapping:
   - Analyze custom attribute names for matches to Okta native user profile attributes
   - Support case-insensitive matching with variation recognition (e.g., first_name → firstName)
   - Fetch profile mapping configuration using `/api/v1/mappings`
   - Create bidirectional mappings from app attributes to Okta user profile
   - Update mapping configuration via POST to `/api/v1/mappings/{id}`
   - Display mapping results (matched/unmatched attributes)
7. Governance Registration & Entitlement Management (NEW - STEP 4):
   - Check if app is registered in Okta Governance (GET /governance/api/v1/resources)
   - If not registered: Attempt to register app as governance resource (POST /governance/api/v1/resources)
   - Enable entitlement management (PUT /governance/api/v1/resources/{id}/entitlement-management)
   - Graceful error handling when governance APIs return 405 (not available/licensed)
   - Provides manual setup instructions when API methods fail
8. Entitlement Catalog & Creation Processing (STEP 7):
   - Parse CSV to find all columns starting with `ent_` prefix
   - Extract unique values from each entitlement column (handles comma-separated values)
   - Fetch governance resource ID for the app
   - Get existing entitlements from governance API
   - Create new entitlements via POST API (skips duplicates)
   - Display catalog with creation status
   - If resource not found: Display catalog with manual setup instructions
9. Report: Show processing complete message

### Configuration Flow

1. Application calls `getConfig()` from config.js
2. Attempts to load config.json
3. If file exists, validates the Okta domain:
   - Must end with `.okta.com` or `.oktapreview.com`
   - If invalid, prompts user to reconfigure
4. If file doesn't exist, prompts user interactively for:
   - Okta Tenant URL (accepts with or without `https://`)
   - Validates domain and loops until valid input provided
   - Strips protocol and trailing slashes before saving
   - API Token (stored as `apiToken`)
5. Saves configuration to config.json for subsequent runs

### Okta API Usage

The application uses direct `fetch()` calls to Okta REST APIs:
- **Search Apps**: `GET /api/v1/apps?q={appName}`
- **Create App**: `POST /api/v1/apps` with SAML 2.0 definition
- **Get App User Schema**: `GET /api/v1/meta/schemas/apps/{appId}/default`
- **Create Custom Attribute**: `POST /api/v1/meta/schemas/apps/{appId}/default`
- **Get Profile Mappings**: `GET /api/v1/mappings?sourceId={appId}`
- **Update Profile Mapping**: `POST /api/v1/mappings/{mappingId}`
- **Get Entitlements**: `GET /api/v1/governance/resources/{appId}/entitlements` (or alternative endpoints)

Authentication uses SSWS token in Authorization header:
```javascript
headers: {
  'Authorization': `SSWS ${config.apiToken}`,
  'Accept': 'application/json'
}
```

### CSV Column Processing

**Custom Attributes:**
- Columns NOT starting with `ent_` are processed as custom app user attributes
- Uses `csv-parse` library to read CSV headers
- Custom attributes are created with type `string` and scope `NONE`
- Checks for duplicates before creation

**Entitlements:**
- Columns starting with `ent_` are processed as entitlements (e.g., ent_UserRole, ent_Permissions)
- Parses entire CSV file to extract all unique values from entitlement columns
- Handles comma-separated values within cells (e.g., "Role1,Role2" becomes ["Role1", "Role2"])
- Deduplicates values and sorts alphabetically
- Checks against Okta Governance API for existing entitlements
- Provides catalog for manual import if API creation is not supported

### SAML App Defaults

Created apps use placeholder values that need manual configuration:
- SSO ACS URL: `https://example.com/sso/saml`
- Audience: `https://example.com/{appName}`
- NameID Format: Email address
- Signing: RSA-SHA256

### Governance & Entitlement Management

**Manual Setup Required:**
Okta Governance APIs for resource registration and entitlement management may return 405 (Method Not Allowed) if:
- Okta Identity Governance (OIG) license is not available
- Governance features are not enabled for the organization
- The app has not been manually added to Identity Governance → Resources

**Manual Steps:**
1. Login to Okta Admin Console
2. Navigate to Identity Governance → Resources
3. Click "Add application" and select the newly created SAML app
4. Enable "Entitlement Management" for the application
5. Re-run the CSV Agent - it will now detect the governance resource and create entitlements

**Once Enabled:**
- The app automatically detects the governance resource ID
- Entitlements are created via POST to `/governance/api/v1/resources/{resourceId}/entitlements`
- Duplicate checking prevents re-creating existing entitlements
- Each entitlement includes: name, attribute (from column name), value (JSON)

### Security

- config.json contains sensitive credentials and is gitignored
- Never commit API tokens or configuration files
- API token needs application management permissions
- API token may also need Okta Identity Governance (OIG) permissions for entitlement creation
