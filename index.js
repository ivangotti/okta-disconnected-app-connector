import okta from '@okta/okta-sdk-nodejs';
const { Client } = okta;
import { getConfig, saveConfig, selectCsvFile, getAccessToken, reconfigureOAuthCredentials } from './config.js';
import fs from 'fs';
import path from 'path';
import { parse } from 'csv-parse/sync';

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  italic: '\x1b[3m',
  underline: '\x1b[4m',
  // Text colors
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  // Bright colors
  brightRed: '\x1b[91m',
  brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m',
  brightBlue: '\x1b[94m',
  brightMagenta: '\x1b[95m',
  brightCyan: '\x1b[96m',
};

// Helper functions for styled output
const style = {
  // Status indicators
  success: (text) => `${colors.green}${text}${colors.reset}`,
  warning: (text) => `${colors.yellow}${text}${colors.reset}`,
  error: (text) => `${colors.red}${text}${colors.reset}`,
  info: (text) => `${colors.cyan}${text}${colors.reset}`,

  // Data highlighting
  id: (text) => `${colors.brightCyan}${text}${colors.reset}`,
  name: (text) => `${colors.brightMagenta}${colors.bold}${text}${colors.reset}`,
  value: (text) => `${colors.brightGreen}${text}${colors.reset}`,
  attr: (text) => `${colors.brightYellow}${text}${colors.reset}`,
  url: (text) => `${colors.blue}${colors.underline}${text}${colors.reset}`,

  // Structural
  label: (text) => `${colors.white}${colors.bold}${text}${colors.reset}`,
  dim: (text) => `${colors.dim}${text}${colors.reset}`,
  bold: (text) => `${colors.bold}${text}${colors.reset}`,
  step: (text) => `${colors.brightBlue}${colors.bold}${text}${colors.reset}`,

  // Numbers and counts
  count: (text) => `${colors.brightYellow}${colors.bold}${text}${colors.reset}`,

  // Status badges
  badge: {
    ok: () => `${colors.green}✓${colors.reset}`,
    fail: () => `${colors.red}✗${colors.reset}`,
    warn: () => `${colors.yellow}⚠${colors.reset}`,
    skip: () => `${colors.gray}⊘${colors.reset}`,
    arrow: () => `${colors.dim}→${colors.reset}`,
    bullet: () => `${colors.dim}•${colors.reset}`,
  }
};

/**
 * Colorize JSON for pretty terminal output
 */
function colorizeJson(obj, indent = 0) {
  const spaces = '  '.repeat(indent);

  if (obj === null) return `${colors.dim}null${colors.reset}`;
  if (obj === undefined) return `${colors.dim}undefined${colors.reset}`;

  if (typeof obj === 'string') {
    return `${colors.green}"${obj}"${colors.reset}`;
  }
  if (typeof obj === 'number') {
    return `${colors.brightYellow}${obj}${colors.reset}`;
  }
  if (typeof obj === 'boolean') {
    return `${colors.brightMagenta}${obj}${colors.reset}`;
  }

  if (Array.isArray(obj)) {
    if (obj.length === 0) return `${colors.dim}[]${colors.reset}`;
    const items = obj.map(item => `${spaces}  ${colorizeJson(item, indent + 1)}`);
    return `[\n${items.join(',\n')}\n${spaces}]`;
  }

  if (typeof obj === 'object') {
    const keys = Object.keys(obj);
    if (keys.length === 0) return `${colors.dim}{}${colors.reset}`;
    const entries = keys.map(key => {
      const coloredKey = `${colors.cyan}"${key}"${colors.reset}`;
      const coloredValue = colorizeJson(obj[key], indent + 1);
      return `${spaces}  ${coloredKey}: ${coloredValue}`;
    });
    return `{\n${entries.join(',\n')}\n${spaces}}`;
  }

  return String(obj);
}

/**
 * Format JSON with colors for console output (compact version for inline)
 */
function formatJsonCompact(obj) {
  if (typeof obj === 'string') return `${colors.green}"${obj}"${colors.reset}`;
  if (typeof obj === 'number') return `${colors.brightYellow}${obj}${colors.reset}`;
  if (typeof obj === 'boolean') return `${colors.brightMagenta}${obj}${colors.reset}`;
  if (obj === null) return `${colors.dim}null${colors.reset}`;

  try {
    const json = JSON.stringify(obj, null, 2);
    return json
      .replace(/"([^"]+)":/g, `${colors.cyan}"$1"${colors.reset}:`)
      .replace(/: "([^"]+)"/g, `: ${colors.green}"$1"${colors.reset}`)
      .replace(/: (\d+)/g, `: ${colors.brightYellow}$1${colors.reset}`)
      .replace(/: (true|false)/g, `: ${colors.brightMagenta}$1${colors.reset}`)
      .replace(/: null/g, `: ${colors.dim}null${colors.reset}`);
  } catch {
    return String(obj);
  }
}

// Global access token cache with expiration tracking
let cachedAccessToken = null;
let tokenExpiresAt = null;

/**
 * Generate a secure random password for new users
 * Meets typical password complexity requirements
 */
function generateSecurePassword() {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*';
  const allChars = lowercase + uppercase + numbers + symbols;

  // Ensure at least one of each required character type
  let password = '';
  password += lowercase[Math.floor(Math.random() * lowercase.length)];
  password += uppercase[Math.floor(Math.random() * uppercase.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  password += symbols[Math.floor(Math.random() * symbols.length)];

  // Fill the rest with random characters (total 16 chars)
  for (let i = 4; i < 16; i++) {
    password += allChars[Math.floor(Math.random() * allChars.length)];
  }

  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}

/**
 * Check if the cached token is expired or about to expire
 * Returns true if token needs refresh (expired or expires within 5 minutes)
 */
function isTokenExpired() {
  if (!tokenExpiresAt) return true;
  // Refresh if token expires within 5 minutes
  const bufferMs = 5 * 60 * 1000;
  return Date.now() >= (tokenExpiresAt - bufferMs);
}

/**
 * Clear the cached token (used on 401 errors to force refresh)
 */
function clearCachedToken() {
  cachedAccessToken = null;
  tokenExpiresAt = null;
}

/**
 * Get authorization header for API calls
 * Supports SSWS API token (preferred) and OAuth client credentials
 * Automatically refreshes expired OAuth tokens
 */
async function getAuthHeader(config, forceRefresh = false) {
  if (config.apiToken) {
    // SSWS API token (preferred)
    return `SSWS ${config.apiToken}`;
  } else if (config.clientId) {
    // OAuth client credentials flow (optional)
    if (!cachedAccessToken || isTokenExpired() || forceRefresh) {
      if (forceRefresh && cachedAccessToken) {
        console.log('   → Token expired or invalid, refreshing...');
      }
      if (config.clientSecret || config.privateKey || config.privateKeyPath) {
        cachedAccessToken = await getAccessToken(config);
        // Client credentials tokens typically last 1 hour (3600 seconds)
        tokenExpiresAt = Date.now() + (60 * 60 * 1000);
      } else {
        throw new Error('Authentication incomplete: OAuth clientId found but missing credentials. API Token (SSWS) is recommended instead.');
      }
      if (forceRefresh) {
        console.log('   ✓ Token refreshed successfully');
      }
    }
    return `Bearer ${cachedAccessToken}`;
  } else {
    throw new Error('No authentication credentials found in configuration');
  }
}

/**
 * Find all CSV files in the current directory
 */
function findCsvFiles() {
  const files = fs.readdirSync('.');
  return files.filter(file => file.endsWith('.csv'));
}

/**
 * Check if an application exists by name
 */
async function findAppByName(config, appName) {
  try {
    const authHeader = await getAuthHeader(config);
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/apps?q=${encodeURIComponent(appName)}`,
      {
        headers: {
          'Authorization': authHeader,
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to search apps: ${response.statusText}`);
    }

    const apps = await response.json();
    return apps.find(app => app.label === appName);
  } catch (error) {
    throw new Error(`Error searching for app: ${error.message}`);
  }
}

/**
 * Create a SAML 2.0 application
 */
async function createSamlApp(config, appName) {
  const appDefinition = {
    label: appName,
    visibility: {
      autoSubmitToolbar: false,
      hide: {
        iOS: false,
        web: false
      }
    },
    features: [],
    signOnMode: 'SAML_2_0',
    settings: {
      signOn: {
        defaultRelayState: '',
        ssoAcsUrl: 'https://example.com/sso/saml',
        idpIssuer: 'http://www.okta.com/${org.externalKey}',
        audience: `https://example.com/${appName}`,
        recipient: 'https://example.com/sso/saml',
        destination: 'https://example.com/sso/saml',
        subjectNameIdTemplate: '${user.userName}',
        subjectNameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        responseSigned: true,
        assertionSigned: true,
        signatureAlgorithm: 'RSA_SHA256',
        digestAlgorithm: 'SHA256',
        honorForceAuthn: true,
        authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      }
    }
  };

  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/apps`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(appDefinition)
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Failed to create app: ${response.statusText} - ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`Error creating app: ${error.message}`);
  }
}

/**
 * Read CSV file and extract column headers
 */
function getCsvColumns(csvFilePath) {
  try {
    const fileContent = fs.readFileSync(csvFilePath, 'utf8');

    // Parse CSV to get headers only (read first 2 lines - header + 1 data row)
    const records = parse(fileContent, {
      columns: true,
      skip_empty_lines: true,
      to_line: 2  // Read header line + first data row
    });

    // Get column names from the parsed data
    const columns = Object.keys(records[0] || {});

    // Return ALL columns (including ent_* entitlement columns)
    return columns;
  } catch (error) {
    throw new Error(`Error reading CSV file: ${error.message}`);
  }
}

/**
 * Read CSV file and extract column headers with details
 */
function getCsvColumnsWithDetails(csvFilePath) {
  try {
    const fileContent = fs.readFileSync(csvFilePath, 'utf8');

    // Parse CSV to get headers only (read first 2 lines - header + 1 data row)
    const records = parse(fileContent, {
      columns: true,
      skip_empty_lines: true,
      to_line: 2  // Read header line + first data row
    });

    // Get column names from the parsed data
    const allColumns = Object.keys(records[0] || {});

    // Standard identity columns that should NOT be created as custom attributes
    // These are used for user identification/login, not as app-specific attributes
    const standardIdentityColumns = [
      'username', 'login', 'email', 'user', 'userid', 'user_id', 'mail',
      'firstname', 'first_name', 'lastname', 'last_name', 'displayname',
      'display_name', 'name', 'fullname', 'full_name'
    ];

    // Filter out:
    // 1. Entitlement columns (ent_*) - handled separately
    // 2. Standard identity columns - used for login, not custom attributes
    const excluded = [];
    const included = allColumns.filter(col => {
      const colLower = col.toLowerCase();
      if (col.startsWith('ent_')) {
        excluded.push(col + ' (entitlement)');
        return false;
      }
      if (standardIdentityColumns.includes(colLower)) {
        excluded.push(col + ' (identity field)');
        return false;
      }
      return true;
    });

    return {
      total: allColumns.length,
      included: included,
      excluded: excluded
    };
  } catch (error) {
    throw new Error(`Error reading CSV file: ${error.message}`);
  }
}

/**
 * Parse CSV and generate entitlement catalog
 * Similar to bundle-mining's catalog generation
 * Extracts unique values from columns prefixed with 'ent_'
 */
function generateEntitlementCatalog(csvFilePath) {
  try {
    const fileContent = fs.readFileSync(csvFilePath, 'utf8');

    // Parse entire CSV file
    const records = parse(fileContent, {
      columns: true,
      skip_empty_lines: true,
      trim: true
    });

    if (records.length === 0) {
      return {};
    }

    // Find all columns that start with 'ent_'
    const entColumns = Object.keys(records[0]).filter(col => col.startsWith('ent_'));

    const catalog = {};

    // Process each entitlement column
    for (const column of entColumns) {
      const uniqueValues = new Set();

      // Extract values from all records
      for (const record of records) {
        const cellValue = record[column];

        if (cellValue && cellValue.trim() !== '') {
          // Split by comma to handle comma-separated values
          const values = cellValue.split(',').map(v => v.trim());

          // Add each value to the set (automatically deduplicates)
          for (const value of values) {
            if (value !== '') {
              uniqueValues.add(value);
            }
          }
        }
      }

      // Convert Set to sorted array
      catalog[column] = Array.from(uniqueValues).sort();
    }

    return catalog;
  } catch (error) {
    throw new Error(`Error generating entitlement catalog: ${error.message}`);
  }
}

/**
 * Register app as a governance resource
 */
async function registerGovernanceResource(config, appId, appName) {
  try {
    // Extract org name from domain (e.g., "idmotors" from "idmotors.okta.com")
    const orgName = config.oktaDomain.split('.')[0];

    // Format the resource name: orgname_appname (lowercase, no spaces)
    const formattedAppName = appName.toLowerCase().replace(/[^a-z0-9]/g, '');
    const resourceName = `${orgName}_${formattedAppName}`;

    console.log(`   → Resource name: ${resourceName}`);

    // Use the opt-in endpoint to enable entitlement management
    const optInUrl = `https://${config.oktaDomain}/api/v1/governance/resources/source/${appId}/optIn`;
    console.log(`   → API Call: POST ${optInUrl}`);

    // Use SSWS token for governance opt-in endpoint if available (governance API preference)
    const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);
    console.log(`   → Using ${config.apiToken ? 'SSWS' : 'OAuth'} authentication`);

    const response = await fetch(optInUrl, {
      method: 'POST',
      headers: {
        'Authorization': authHeader,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name: resourceName,
        rampResourceType: 'OKTA_APP'
      })
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    const result = await response.json();
    console.log(`   ✓ Entitlement management enabled successfully`);
    return result;
  } catch (error) {
    throw new Error(`Error enabling entitlement management: ${error.message}`);
  }
}

/**
 * Enable entitlement management for an app in Okta Governance
 */
async function enableEntitlementManagement(config, resourceId) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/resources/${resourceId}/entitlement-management`,
      {
        method: 'PUT',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          status: 'ENABLED'
        })
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`${error.message}`);
  }
}

/**
 * Create an entitlement in Okta Governance
 */
async function createEntitlement(config, resourceId, entitlementData) {
  try {
    // Use SSWS token for governance endpoints if available
    const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

    // Use top-level entitlements endpoint (not under resources)
    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/entitlements`,
      {
        method: 'POST',
        headers: {
          'Authorization': authHeader,
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(entitlementData)
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`${error.message}`);
  }
}

/**
 * Get resource ID for an app in Okta Governance
 */
async function getGovernanceResourceId(config, appId) {
  try {
    // Try to get the resource by querying governance resources
    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/resources?filter=source.id eq "${appId}"`,
      {
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      return null;
    }

    const resources = await response.json();
    if (resources && resources.length > 0) {
      return resources[0].id;
    }

    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Fetch entitlement by name from Okta Governance
 * Used when we need to get an existing entitlement that we couldn't create
 */
async function getEntitlementByName(config, appId, entitlementName) {
  const maxRetries = 3;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

      // Try to filter by name and parent application
      const filter = encodeURIComponent(`name eq "${entitlementName}" and parent.externalId eq "${appId}"`);
      const response = await fetch(
        `https://${config.oktaDomain}/governance/api/v1/entitlements?filter=${filter}`,
        {
          headers: {
            'Authorization': authHeader,
            'Accept': 'application/json'
          }
        }
      );

      // Handle rate limiting
      if (response.status === 429) {
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, 5000 * attempt));
          continue;
        }
      }

      if (response.ok) {
        const result = await response.json();
        if (Array.isArray(result) && result.length > 0) {
          return result[0];
        }
      }

      // If filter didn't work, try without filter and search manually
      const allResponse = await fetch(
        `https://${config.oktaDomain}/governance/api/v1/entitlements?limit=200`,
        {
          headers: {
            'Authorization': authHeader,
            'Accept': 'application/json'
          }
        }
      );

      // Handle rate limiting
      if (allResponse.status === 429) {
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, 5000 * attempt));
          continue;
        }
      }

      if (allResponse.ok) {
        const allEntitlements = await allResponse.json();
        if (Array.isArray(allEntitlements)) {
          const found = allEntitlements.find(ent =>
            ent.name && ent.name.toLowerCase() === entitlementName.toLowerCase() &&
            ent.parent && ent.parent.externalId === appId
          );
          if (found) return found;
        }
      }

      // If we got here without finding it, wait and retry
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    } catch (error) {
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        continue;
      }
    }
  }

  return null;
}

/**
 * Get existing entitlements for an app
 * Tries multiple endpoint patterns to find the correct one
 */
async function getAppEntitlements(config, resourceId, appId) {
  try {
    // Use SSWS token for governance endpoints if available
    const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

    // Try multiple filter approaches as the governance API is inconsistent
    const filterOptions = [
      `parent.externalId eq "${appId}"`,  // Match on parent's external ID (app ID)
      `resource.id eq "${resourceId}"`,    // Match on resource ID
      `parent.id eq "${resourceId}"`       // Match on parent ID
    ];

    for (const filterExpr of filterOptions) {
      try {
        const filter = encodeURIComponent(filterExpr);
        const response = await fetch(
          `https://${config.oktaDomain}/governance/api/v1/entitlements?filter=${filter}`,
          {
            headers: {
              'Authorization': authHeader,
              'Accept': 'application/json'
            }
          }
        );

        if (response.ok) {
          const result = await response.json();
          // If we got results, return them
          if (Array.isArray(result) && result.length > 0) {
            return result;
          }
        }
      } catch (filterError) {
        // Try next filter
        continue;
      }
    }

    // If all filters failed, throw error
    throw new Error(`Unable to fetch entitlements - tried multiple filter approaches`);
  } catch (error) {
    throw error;
  }
}

/**
 * Add a new value to an existing entitlement
 * Used when sync detects a new entitlement value that doesn't exist yet
 */
async function addEntitlementValue(config, entitlementId, valueName, appId) {
  try {
    const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

    // First get the current entitlement to see its structure
    const getResponse = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/entitlements/${entitlementId}`,
      {
        headers: {
          'Authorization': authHeader,
          'Accept': 'application/json'
        }
      }
    );

    if (!getResponse.ok) {
      throw new Error(`Failed to get entitlement: HTTP ${getResponse.status}`);
    }

    const currentEntitlement = await getResponse.json();

    // Add the new value to the existing values array
    const existingValues = currentEntitlement.values || [];
    const newValue = {
      name: valueName,
      description: valueName,
      externalValue: valueName
    };

    // Update the entitlement with the new value added
    const updatedEntitlement = {
      ...currentEntitlement,
      values: [...existingValues, newValue]
    };

    // PUT to update the entitlement
    const updateResponse = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/entitlements/${entitlementId}`,
      {
        method: 'PUT',
        headers: {
          'Authorization': authHeader,
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(updatedEntitlement)
      }
    );

    if (!updateResponse.ok) {
      const errorBody = await updateResponse.text();
      throw new Error(`Failed to update entitlement: HTTP ${updateResponse.status}: ${errorBody}`);
    }

    const result = await updateResponse.json();

    // Find and return the newly created value from the result
    const createdValue = result.values?.find(v =>
      v.name && v.name.toLowerCase() === valueName.toLowerCase()
    );

    return createdValue || null;
  } catch (error) {
    throw new Error(`Failed to add entitlement value "${valueName}": ${error.message}`);
  }
}

/**
 * Process entitlement catalog and create entitlements in Okta
 */
async function processEntitlements(config, appId, csvFilePath, existingResourceId = null) {
  console.log('');
  console.log(`📦 ${style.step('STEP 7: Entitlement Catalog & Creation')}`);
  console.log(`   ${style.badge.arrow()} Parsing CSV file for entitlement columns ${style.dim('(ent_*)')}...`);

  const catalog = generateEntitlementCatalog(csvFilePath);
  const entColumns = Object.keys(catalog);

  if (entColumns.length === 0) {
    console.log(`   ${style.info('ℹ')} No entitlement columns found in CSV`);
    console.log(`   ${style.badge.arrow()} ${style.dim('Entitlement columns must start with "ent_" prefix')}`);
    console.log('');
    return;
  }

  console.log(`   ${style.badge.ok()} Found ${style.count(entColumns.length)} entitlement column(s):`);
  let totalEntitlements = 0;
  for (const [column, values] of Object.entries(catalog)) {
    console.log(`     ${style.badge.bullet()} ${style.attr(column)}: ${style.count(values.length)} unique value(s)`);
    totalEntitlements += values.length;
  }
  console.log(`   ${style.badge.arrow()} Total unique entitlements to create: ${style.count(totalEntitlements)}`);
  console.log('');

  // Use existing resource ID if provided, otherwise fetch it
  let resourceId = existingResourceId;

  if (!resourceId) {
    console.log(`   ${style.badge.arrow()} Fetching governance resource ID for app...`);
    console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('GET /governance/api/v1/resources?filter=source.id eq "' + appId + '"')}`);
    resourceId = await getGovernanceResourceId(config, appId);
  } else {
    console.log(`   ${style.badge.arrow()} Using governance resource ID from Step 4: ${style.id(resourceId)}`);
  }

  if (!resourceId) {
    console.log(`   ${style.badge.warn()} ${style.warning('Could not find governance resource for this app')}`);
    console.log(`   ${style.badge.arrow()} ${style.dim('Entitlement management may not be enabled yet')}`);
    console.log(`   ${style.badge.arrow()} ${style.dim('Try enabling it in Okta Admin Console: Identity Governance → Resources')}`);
    console.log('');
    console.log(`   📋 ${style.label('Entitlement Catalog Summary:')}`);
    for (const [column, values] of Object.entries(catalog)) {
      const attributeName = column.substring(4); // Remove 'ent_' prefix
      console.log(`     ${style.badge.bullet()} ${style.attr(attributeName)}: ${style.value(values.join(', '))}`);
    }
    console.log('');
    return;
  }

  console.log(`   ${style.badge.ok()} Governance resource found: ${style.id(resourceId)}`);
  console.log('');

  // Check existing entitlements
  console.log(`   ${style.badge.arrow()} Fetching existing entitlements...`);
  console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('GET /governance/api/v1/resources/' + resourceId + '/entitlements')}`);

  let existingEntitlements = [];
  try {
    existingEntitlements = await getAppEntitlements(config, resourceId, appId);
  } catch (error) {
    if (error.message.includes('405')) {
      console.log(`   ${style.badge.warn()} ${style.warning('Cannot fetch existing entitlements')} ${style.dim('(HTTP 405)')}`);
      console.log(`   ${style.badge.arrow()} ${style.dim('Assuming no existing entitlements, will attempt to create all')}`);
      console.log('');
    } else {
      console.log(`   ${style.badge.warn()} ${style.warning('Could not fetch entitlements from governance API:')} ${error.message}`);
      console.log(`   ${style.badge.arrow()} ${style.dim('Proceeding to create entitlements')}`);
      console.log('');
    }
    // Continue with empty array - we'll try to create all entitlements
    existingEntitlements = [];
  }

  if (existingEntitlements === null) {
    existingEntitlements = [];
  }

  console.log(`   ${style.badge.ok()} Found ${style.count(existingEntitlements.length)} existing entitlements`);
  console.log('');

  // Create entitlements from catalog
  console.log(`   ${style.badge.arrow()} Creating entitlements from CSV catalog...`);
  console.log('');

  let created = 0;
  let skipped = 0;
  let failed = 0;
  const createdEntitlements = {}; // Track created entitlements for later use

  // Create ONE entitlement per column (attribute) with all values
  for (const [column, values] of Object.entries(catalog)) {
    const attributeName = column.substring(4); // Remove 'ent_' prefix
    console.log(`   ${style.badge.arrow()} Creating ${style.attr(attributeName)} entitlement with ${style.count(values.length)} value(s):`);

    try {
      // Check if entitlement already exists
      const existingEnt = existingEntitlements.find(ent =>
        ent.name && ent.name.toLowerCase() === attributeName.toLowerCase()
      );

      if (existingEnt) {
        console.log(`     ${style.badge.skip()} ${style.attr(attributeName)} entitlement already exists ${style.dim('(skipped)')}`);
        // Store existing entitlement for later use
        createdEntitlements[attributeName.toLowerCase()] = existingEnt;
        skipped++;
        console.log('');
        continue;
      }

      // Build entitlement data in correct API format
      const entitlementData = {
        name: attributeName,
        externalValue: attributeName,
        description: `${attributeName} entitlement from CSV`,
        parent: {
          externalId: appId,
          type: 'APPLICATION'
        },
        multiValue: true,
        dataType: 'string',
        values: values.map(value => ({
          name: value,
          description: value,
          externalValue: value
        }))
      };

      console.log(`     ${style.badge.arrow()} Values: ${style.value(values.join(', '))}`);
      const newEntitlement = await createEntitlement(config, resourceId, entitlementData);
      console.log(`     ${style.badge.ok()} ${style.attr(attributeName)} entitlement created with ${style.count(values.length)} value(s)`);

      // Store the created entitlement for later use
      if (newEntitlement && newEntitlement.id) {
        createdEntitlements[attributeName.toLowerCase()] = newEntitlement;
      }
      created++;
    } catch (error) {
      // Check if error is because entitlement already exists
      if (error.message.includes('needs to be unique')) {
        console.log(`     ${style.badge.skip()} ${style.attr(attributeName)} entitlement already exists, fetching...`);
        try {
          const existingEnt = await getEntitlementByName(config, appId, attributeName);
          if (existingEnt && existingEnt.id) {
            console.log(`     ${style.badge.ok()} Found existing ${style.attr(attributeName)} entitlement ${style.dim('(' + existingEnt.id + ')')}`);
            createdEntitlements[attributeName.toLowerCase()] = existingEnt;
            skipped++;
          } else {
            console.log(`     ${style.badge.warn()} ${style.warning('Could not fetch existing')} ${style.attr(attributeName)} entitlement`);
            failed++;
          }
        } catch (fetchError) {
          console.log(`     ${style.badge.warn()} ${style.warning('Error fetching existing entitlement:')} ${fetchError.message}`);
          failed++;
        }
      } else {
        console.log(`     ${style.badge.fail()} ${style.attr(attributeName)} ${style.error('failed:')} ${error.message}`);
        failed++;
      }
    }
    console.log('');
  }

  console.log(`   📊 ${style.label('Entitlement Creation Summary:')}`);
  console.log(`     ${style.badge.bullet()} Total entitlement columns: ${style.count(Object.keys(catalog).length)}`);
  console.log(`     ${style.badge.bullet()} ${style.success('Successfully created:')} ${style.count(created)}`);
  console.log(`     ${style.badge.bullet()} Already existed: ${style.count(skipped)}`);
  if (failed > 0) {
    console.log(`     ${style.badge.bullet()} ${style.error('Failed:')} ${style.count(failed)}`);
  }
  console.log('');

  // Return the entitlements map for use in user provisioning
  return createdEntitlements;
}

/**
 * Check if user exists in Okta by login/email
 */
async function findUser(config, login) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/users/${encodeURIComponent(login)}`,
      {
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json'
        }
      }
    );

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }

    return await response.json();
  } catch (error) {
    if (error.message.includes('404')) {
      return null;
    }
    throw error;
  }
}

/**
 * Create user in Okta
 */
async function createUser(config, userData) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/users?activate=true`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw error;
  }
}

/**
 * Update user in Okta
 */
async function updateUser(config, userId, userData) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/users/${userId}`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw error;
  }
}

/**
 * Assign user to app with profile attributes
 */
async function assignUserToApp(config, appId, userId, profileData) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/apps/${appId}/users`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          id: userId,
          scope: 'USER',
          profile: profileData
        })
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw error;
  }
}

/**
 * Create entitlement grant for a user using the correct Okta Governance API format
 * Creates a single grant with all user entitlements
 */
async function createEntitlementGrant(config, appId, userId, entitlementsArray) {
  try {
    // Use SSWS token for governance endpoints if available
    const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

    // Build the grant payload in the correct Okta format
    const grantData = {
      grantType: "CUSTOM",
      targetPrincipal: {
        externalId: userId,
        type: "OKTA_USER"
      },
      actor: "ADMIN",
      target: {
        externalId: appId,
        type: "APPLICATION"
      },
      entitlements: entitlementsArray
    };

    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/grants`,
      {
        method: 'POST',
        headers: {
          'Authorization': authHeader,
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(grantData)
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw error;
  }
}

/**
 * Get all users assigned to an app
 */
async function getAppUsers(config, appId) {
  try {
    const allUsers = [];
    let url = `https://${config.oktaDomain}/api/v1/apps/${appId}/users?limit=200`;

    while (url) {
      const response = await fetch(url, {
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${await response.text()}`);
      }

      const users = await response.json();
      allUsers.push(...users);

      // Check for pagination
      const linkHeader = response.headers.get('link');
      if (linkHeader && linkHeader.includes('rel="next"')) {
        const match = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
        url = match ? match[1] : null;
      } else {
        url = null;
      }
    }

    return allUsers;
  } catch (error) {
    throw error;
  }
}

/**
 * Unassign user from app
 */
async function unassignUserFromApp(config, appId, userId) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/apps/${appId}/users/${userId}`,
      {
        method: 'DELETE',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok && response.status !== 204) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return true;
  } catch (error) {
    throw error;
  }
}

/**
 * Update app user profile
 */
async function updateAppUserProfile(config, appId, userId, profileData) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/apps/${appId}/users/${userId}`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          profile: profileData
        })
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw error;
  }
}

/**
 * Get user's entitlement grants for an app
 */
async function getUserGrants(config, appId, userId) {
  try {
    const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

    // Filter grants by user and app
    const filter = encodeURIComponent(`targetPrincipal.externalId eq "${userId}" and target.externalId eq "${appId}"`);
    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/grants?filter=${filter}`,
      {
        headers: {
          'Authorization': authHeader,
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      // If filter doesn't work, return empty array
      return [];
    }

    const grants = await response.json();
    return Array.isArray(grants) ? grants : [];
  } catch (error) {
    return [];
  }
}

/**
 * Revoke an entitlement grant
 */
async function revokeGrant(config, grantId) {
  try {
    const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/grants/${grantId}`,
      {
        method: 'DELETE',
        headers: {
          'Authorization': authHeader,
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok && response.status !== 204) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return true;
  } catch (error) {
    throw error;
  }
}

/**
 * Process users from CSV - create/update users and assign to app
 */
async function processUsers(config, appId, csvFilePath, resourceId = null, entitlementsMap = {}) {
  console.log(`👥 ${style.step('STEP 8: User Provisioning')}`);
  console.log(`   ${style.badge.arrow()} Reading user data from CSV...`);

  try {
    const fileContent = fs.readFileSync(csvFilePath, 'utf8');
    const records = parse(fileContent, {
      columns: true,
      skip_empty_lines: true,
      trim: true
    });

    console.log(`   ${style.badge.ok()} Found ${style.count(records.length)} user(s) in CSV`);
    console.log('');

    let created = 0;
    let updated = 0;
    let assigned = 0;
    let grantsCreated = 0;
    let failed = 0;

    for (let i = 0; i < records.length; i++) {
      const record = records[i];

      // Dynamically find username/login column (try common variations)
      const usernameKeys = ['username', 'login', 'email', 'user', 'userid', 'user_id', 'mail'];
      let username = null;
      for (const key of usernameKeys) {
        const matchingCol = Object.keys(record).find(col => col.toLowerCase() === key);
        if (matchingCol && record[matchingCol]) {
          username = record[matchingCol];
          break;
        }
      }

      if (!username) {
        console.log(`   ${style.badge.warn()} ${style.warning('Skipping row')} - no username/email column found ${style.dim('(tried: ' + usernameKeys.join(', ') + ')')}`);
        failed++;
        continue;
      }

      // Declare variables outside try block so they're accessible in catch for retry
      let userId;
      let appUserProfile;

      try {
        console.log(`   ${style.badge.arrow()} Processing user ${style.dim(i + 1 + '/' + records.length)}: ${style.name(username)}`);

        // Build user profile dynamically from CSV columns using attribute mapping
        const userProfile = {
          login: username,
          email: username // Default email to username if not found
        };

        // Dynamically map CSV columns to Okta user profile fields
        for (const [csvColumn, value] of Object.entries(record)) {
          if (!value || csvColumn.startsWith('ent_')) continue; // Skip empty and entitlement columns

          const oktaAttribute = findMatchingOktaAttribute(csvColumn);
          if (oktaAttribute) {
            userProfile[oktaAttribute] = value;
          }
        }

        // Ensure required fields have at least empty values
        if (!userProfile.firstName) userProfile.firstName = '';
        if (!userProfile.lastName) userProfile.lastName = '';

        // Check if user exists
        const existingUser = await findUser(config, username);
        if (existingUser) {
          console.log(`     ${style.badge.arrow()} User exists ${style.dim('(' + existingUser.id + ')')}, updating...`);
          await updateUser(config, existingUser.id, { profile: userProfile });
          userId = existingUser.id;
          updated++;
        } else {
          console.log(`     ${style.badge.arrow()} User does not exist, creating...`);
          // Generate a random secure password for new users
          const randomPassword = generateSecurePassword();
          const newUser = await createUser(config, {
            profile: userProfile,
            credentials: {
              password: { value: randomPassword }
            }
          });
          userId = newUser.id;
          created++;
          console.log(`     ${style.badge.ok()} User created ${style.dim('(' + userId + ')')} - ${style.dim('password reset required on first login')}`);
        }

        // Build app user profile with ONLY valid custom attributes
        // Exclude identity columns (used for login) and entitlement columns (handled via grants)
        appUserProfile = {};

        // Standard identity columns to exclude from app user profile
        const identityColumns = [
          'username', 'login', 'email', 'user', 'userid', 'user_id', 'mail',
          'firstname', 'first_name', 'lastname', 'last_name', 'displayname',
          'display_name', 'name', 'fullname', 'full_name'
        ];

        for (const [key, value] of Object.entries(record)) {
          if (!value) continue;
          // Skip entitlement columns (ent_*) - handled via governance grants
          if (key.startsWith('ent_')) continue;
          // Skip identity columns - used for user identification, not app attributes
          if (identityColumns.includes(key.toLowerCase())) continue;
          appUserProfile[key] = value;
        }

        // Assign user to app with custom attributes only
        console.log(`     ${style.badge.arrow()} Assigning user to app...`);
        await assignUserToApp(config, appId, userId, appUserProfile);
        console.log(`     ${style.badge.ok()} User assigned to app with attributes`);
        assigned++;

        // Create governance grant with entitlements
        if (resourceId && Object.keys(entitlementsMap).length > 0) {
          // Build entitlements array in correct format for Grants API
          const entitlementsForGrant = {};

          // Parse ent_* columns for this user
          for (const [key, value] of Object.entries(record)) {
            if (key.startsWith('ent_') && value) {
              const entitlementName = key.substring(4); // Remove 'ent_' prefix
              const entitlement = entitlementsMap[entitlementName.toLowerCase()];

              if (entitlement && entitlement.id && entitlement.values) {
                // Split comma-separated values and deduplicate
                const csvValues = [...new Set(value.split(',').map(v => v.trim()).filter(v => v))];

                // Find matching value IDs
                for (const val of csvValues) {
                  let entValue = entitlement.values.find(
                    ev => ev.name && ev.name.toLowerCase() === val.toLowerCase()
                  );

                  // If value doesn't exist, create it dynamically
                  if (!entValue || !entValue.id) {
                    try {
                      console.log(`     ${style.badge.arrow()} New entitlement value detected: ${style.value('"' + val + '"')} for ${style.attr(entitlementName)}`);
                      console.log(`       Creating new value in Okta...`);
                      const newValue = await addEntitlementValue(config, entitlement.id, val, appId);
                      if (newValue && newValue.id) {
                        console.log(`       ${style.badge.ok()} Created new entitlement value: ${style.value(val)} ${style.dim('(' + newValue.id + ')')}`);
                        // Add to local cache so we don't try to create again
                        entitlement.values.push(newValue);
                        entValue = newValue;
                      } else {
                        console.log(`       ${style.badge.warn()} ${style.warning('Could not create entitlement value:')} ${val}`);
                        continue;
                      }
                    } catch (createError) {
                      console.log(`       ${style.badge.warn()} ${style.warning('Failed to create entitlement value:')} ${createError.message}`);
                      continue;
                    }
                  }

                  if (entValue && entValue.id) {
                    // Group by entitlement ID
                    if (!entitlementsForGrant[entitlement.id]) {
                      entitlementsForGrant[entitlement.id] = {
                        id: entitlement.id,
                        values: []
                      };
                    }
                    // Check if this value ID is already added (avoid duplicates)
                    const alreadyAdded = entitlementsForGrant[entitlement.id].values.some(
                      v => v.id === entValue.id
                    );
                    if (!alreadyAdded) {
                      // Include full value object with id, name, description, and label
                      entitlementsForGrant[entitlement.id].values.push({
                        id: entValue.id,
                        name: entValue.name || val,
                        description: entValue.description || val,
                        label: entValue.name || val
                      });
                    }
                  }
                }
              }
            }
          }

          // Convert to array
          const entitlementsArray = Object.values(entitlementsForGrant);

          if (entitlementsArray.length > 0) {
            try {
              console.log(`     ${style.badge.arrow()} Creating governance grant with ${style.count(entitlementsArray.length)} entitlement(s)...`);

              // Debug: log the payload for first user
              if (i === 0) {
                const debugPayload = {
                  grantType: "CUSTOM",
                  targetPrincipal: { externalId: userId, type: "OKTA_USER" },
                  actor: "ADMIN",
                  target: { externalId: appId, type: "APPLICATION" },
                  entitlements: entitlementsArray
                };
                console.log(`     ${style.badge.arrow()} ${style.dim('Debug payload:')}`);
                console.log(formatJsonCompact(debugPayload).split('\n').map(line => `       ${line}`).join('\n').substring(0, 1200));
              }

              await createEntitlementGrant(config, appId, userId, entitlementsArray);
              console.log(`     ${style.badge.ok()} ${style.success('Governance grant created')}`);
              grantsCreated++;
            } catch (error) {
              console.log(`     ${style.badge.warn()} ${style.warning('Grant creation failed:')} ${error.message}`);
              // Don't fail the whole user - they're still assigned to the app
            }
          }
        }

        console.log('');

        // Add small delay to avoid rate limits (every 10 users)
        if ((i + 1) % 10 === 0 && i + 1 < records.length) {
          console.log(`   ${style.dim('⏸  Pausing briefly to avoid rate limits...')} ${style.dim('(' + (i + 1) + '/' + records.length + ' processed)')}`);
          await new Promise(resolve => setTimeout(resolve, 2000));
          console.log('');
        }
      } catch (error) {
        if (error.message.includes('429')) {
          console.log(`     ${style.badge.warn()} ${style.warning('Rate limit hit, waiting 5 seconds...')}`);
          await new Promise(resolve => setTimeout(resolve, 5000));
          // Retry once
          try {
            await assignUserToApp(config, appId, userId, appUserProfile);
            console.log(`     ${style.badge.ok()} User assigned to app with attributes ${style.dim('(retry succeeded)')}`);
            assigned++;
          } catch (retryError) {
            console.log(`     ${style.badge.fail()} ${style.error('Failed after retry:')} ${retryError.message}`);
            failed++;
          }
        } else {
          console.log(`     ${style.badge.fail()} ${style.error('Failed:')} ${error.message}`);
          failed++;
        }
        console.log('');
      }
    }

    console.log(`   📊 ${style.label('User Provisioning Summary:')}`);
    console.log(`     ${style.badge.bullet()} Total users in CSV: ${style.count(records.length)}`);
    console.log(`     ${style.badge.bullet()} ${style.success('Created:')} ${style.count(created)}`);
    console.log(`     ${style.badge.bullet()} Updated: ${style.count(updated)}`);
    console.log(`     ${style.badge.bullet()} Assigned to app: ${style.count(assigned)}`);
    if (grantsCreated > 0) {
      console.log(`     ${style.badge.bullet()} Governance grants created: ${style.count(grantsCreated)}`);
    }
    if (failed > 0) {
      console.log(`     ${style.badge.bullet()} ${style.error('Failed:')} ${style.count(failed)}`);
    }
    console.log('');

  } catch (error) {
    console.log(`   ${style.badge.fail()} ${style.error('Error processing users:')} ${error.message}`);
    console.log('');
  }
}

/**
 * Get current app user schema
 */
async function getAppUserSchema(config, appId) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/meta/schemas/apps/${appId}/default`,
      {
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get app user schema: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`Error getting app user schema: ${error.message}`);
  }
}

/**
 * Get Okta native user profile attributes
 * These are the standard attributes in Okta Universal Directory
 */
function getOktaNativeAttributes() {
  return {
    // Core attributes
    'login': 'login',
    'email': 'email',
    'username': 'login',

    // Name attributes
    'firstname': 'firstName',
    'first_name': 'firstName',
    'fname': 'firstName',
    'givenname': 'firstName',
    'lastname': 'lastName',
    'last_name': 'lastName',
    'lname': 'lastName',
    'surname': 'lastName',
    'familyname': 'lastName',
    'middlename': 'middleName',
    'middle_name': 'middleName',
    'displayname': 'displayName',
    'display_name': 'displayName',
    'nickname': 'nickName',
    'nick_name': 'nickName',

    // Title and prefix
    'title': 'title',
    'jobtitle': 'title',
    'job_title': 'title',
    'honorificprefix': 'honorificPrefix',
    'prefix': 'honorificPrefix',
    'honorificsuffix': 'honorificSuffix',
    'suffix': 'honorificSuffix',

    // Contact attributes
    'primaryphone': 'primaryPhone',
    'primary_phone': 'primaryPhone',
    'phone': 'primaryPhone',
    'phonenumber': 'primaryPhone',
    'mobilephone': 'mobilePhone',
    'mobile_phone': 'mobilePhone',
    'mobile': 'mobilePhone',
    'cellphone': 'mobilePhone',

    // Address attributes
    'streetaddress': 'streetAddress',
    'street_address': 'streetAddress',
    'address': 'streetAddress',
    'street': 'streetAddress',
    'city': 'city',
    'state': 'state',
    'stateprovince': 'state',
    'province': 'state',
    'zipcode': 'zipCode',
    'zip_code': 'zipCode',
    'zip': 'zipCode',
    'postalcode': 'zipCode',
    'postal_code': 'zipCode',
    'countrycode': 'countryCode',
    'country_code': 'countryCode',
    'country': 'countryCode',
    'postaladdress': 'postalAddress',
    'postal_address': 'postalAddress',

    // Locale and language
    'preferredlanguage': 'preferredLanguage',
    'preferred_language': 'preferredLanguage',
    'language': 'preferredLanguage',
    'locale': 'locale',
    'timezone': 'timezone',
    'time_zone': 'timezone',

    // Organization attributes
    'usertype': 'userType',
    'user_type': 'userType',
    'employeenumber': 'employeeNumber',
    'employee_number': 'employeeNumber',
    'employeeid': 'employeeNumber',
    'employee_id': 'employeeNumber',
    'costcenter': 'costCenter',
    'cost_center': 'costCenter',
    'organization': 'organization',
    'org': 'organization',
    'company': 'organization',
    'division': 'division',
    'department': 'department',
    'dept': 'department',
    'managerid': 'managerId',
    'manager_id': 'managerId',
    'manager': 'manager',

    // Profile
    'profileurl': 'profileUrl',
    'profile_url': 'profileUrl'
  };
}

/**
 * Find matching Okta native attribute for a custom attribute name
 */
function findMatchingOktaAttribute(attributeName) {
  const nativeAttributes = getOktaNativeAttributes();
  const normalizedName = attributeName.toLowerCase().replace(/[-_\s]/g, '');

  return nativeAttributes[normalizedName] || null;
}

/**
 * Get app-to-user profile mapping
 */
async function getProfileMapping(config, appId) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/mappings?sourceId=${appId}`,
      {
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to get profile mappings: ${response.statusText}`);
    }

    const mappings = await response.json();
    // Find the mapping from app to user
    return mappings.find(m => m.target.type === 'user');
  } catch (error) {
    throw new Error(`Error getting profile mapping: ${error.message}`);
  }
}

/**
 * Update profile mapping to add attribute mapping
 */
async function updateProfileMapping(config, mappingId, mappingProperties) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/mappings/${mappingId}`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(mappingProperties)
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Failed to update profile mapping: ${response.statusText} - ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`Error updating profile mapping: ${error.message}`);
  }
}

/**
 * Create a custom attribute in app user schema
 */
async function createCustomAttribute(config, appId, attributeName) {
  const customAttributeDefinition = {
    definitions: {
      custom: {
        id: '#custom',
        type: 'object',
        properties: {
          [attributeName]: {
            title: attributeName,
            description: `Custom attribute: ${attributeName}`,
            type: 'string',
            scope: 'NONE',
            master: {
              type: 'PROFILE_MASTER'
            }
          }
        },
        required: []
      }
    }
  };

  try {
    const response = await fetch(
      `https://${config.oktaDomain}/api/v1/meta/schemas/apps/${appId}/default`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(customAttributeDefinition)
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Failed to create custom attribute: ${response.statusText} - ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`Error creating custom attribute: ${error.message}`);
  }
}

/**
 * Process attribute mappings from app to Okta user profile
 */
async function processAttributeMappings(config, appId, createdAttributes) {
  if (createdAttributes.length === 0) {
    return;
  }

  console.log('');
  console.log(`🔗 ${style.step('STEP 6: Profile Attribute Mapping')}`);
  console.log(`   ${style.badge.arrow()} Analyzing custom attributes for Okta user profile mappings...`);
  console.log('');

  // Find matching Okta attributes
  const matchedAttributes = [];
  const unmatchedAttributes = [];

  for (const attributeName of createdAttributes) {
    const oktaAttribute = findMatchingOktaAttribute(attributeName);
    if (oktaAttribute) {
      matchedAttributes.push({
        customAttribute: attributeName,
        oktaAttribute: oktaAttribute
      });
    } else {
      unmatchedAttributes.push(attributeName);
    }
  }

  console.log(`   ${style.badge.arrow()} Matched attributes: ${style.count(matchedAttributes.length)}`);
  if (matchedAttributes.length > 0) {
    matchedAttributes.forEach(match => {
      console.log(`     ${style.badge.bullet()} ${style.attr(match.customAttribute)} ${style.dim('→')} ${style.value('user.' + match.oktaAttribute)}`);
    });
  }
  console.log('');

  if (unmatchedAttributes.length > 0) {
    console.log(`   ${style.badge.arrow()} Unmatched attributes ${style.dim('(no standard Okta field)')}: ${style.count(unmatchedAttributes.length)}`);
    unmatchedAttributes.forEach(attr => {
      console.log(`     ${style.badge.bullet()} ${style.attr(attr)} ${style.dim('(will remain as custom attribute only)')}`);
    });
    console.log('');
  }

  if (matchedAttributes.length === 0) {
    console.log(`   ${style.info('ℹ')} No attributes matched Okta user profile fields`);
    console.log(`   ${style.badge.arrow()} ${style.dim('Skipping profile mapping')}`);
    return;
  }

  // Get the profile mapping
  console.log(`   ${style.badge.arrow()} Fetching profile mapping configuration...`);
  console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('GET /api/v1/mappings?sourceId=' + appId)}`);
  const profileMapping = await getProfileMapping(config, appId);

  if (!profileMapping) {
    console.log(`   ${style.badge.fail()} ${style.error('Profile mapping not found for this application')}`);
    console.log(`   ${style.badge.arrow()} ${style.dim('This may happen if the app was just created')}`);
    console.log(`   ${style.badge.arrow()} ${style.dim('Mappings can be configured manually in Okta Admin Console')}`);
    return;
  }

  console.log(`   ${style.badge.ok()} Profile mapping found ${style.dim('(ID: ' + profileMapping.id + ')')}`);
  console.log('');

  // Build mapping properties
  const currentProperties = profileMapping.properties || {};
  let mappingsAdded = 0;
  let mappingsSkipped = 0;

  console.log(`   ${style.badge.arrow()} Creating attribute mappings...`);
  console.log('');

  for (const match of matchedAttributes) {
    const mappingKey = match.oktaAttribute;

    // Check if mapping already exists
    if (currentProperties[mappingKey]) {
      console.log(`   ${style.badge.arrow()} Mapping for ${style.attr(match.customAttribute)}:`);
      console.log(`     ${style.info('ℹ')} Already exists: ${style.value('user.' + mappingKey)}`);
      mappingsSkipped++;
    } else {
      console.log(`   ${style.badge.arrow()} Mapping for ${style.attr(match.customAttribute)}:`);
      console.log(`     ${style.badge.ok()} Creating: ${style.attr('appuser.' + match.customAttribute)} ${style.dim('→')} ${style.value('user.' + mappingKey)}`);

      // Add new mapping
      currentProperties[mappingKey] = {
        expression: `appuser.${match.customAttribute}`
      };
      mappingsAdded++;
    }
    console.log('');
  }

  // Update the mapping if we added any
  if (mappingsAdded > 0) {
    console.log(`   ${style.badge.arrow()} Updating profile mapping with ${style.count(mappingsAdded)} new mapping(s)...`);
    console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('POST /api/v1/mappings/' + profileMapping.id)}`);

    const updatedMapping = {
      properties: currentProperties
    };

    await updateProfileMapping(config, profileMapping.id, updatedMapping);
    console.log(`   ${style.badge.ok()} ${style.success('Profile mappings updated successfully')}`);
  } else {
    console.log(`   ${style.info('ℹ')} All matching attributes already have mappings`);
  }

  console.log('');
  console.log(`   📊 ${style.label('Mapping Summary:')}`);
  console.log(`     ${style.badge.bullet()} Total attributes analyzed: ${style.count(createdAttributes.length)}`);
  console.log(`     ${style.badge.bullet()} Matched to Okta fields: ${style.count(matchedAttributes.length)}`);
  console.log(`     ${style.badge.bullet()} ${style.success('Mappings created:')} ${style.count(mappingsAdded)}`);
  console.log(`     ${style.badge.bullet()} Mappings already existed: ${style.count(mappingsSkipped)}`);
  console.log(`     ${style.badge.bullet()} Unmatched attributes: ${style.count(unmatchedAttributes.length)}`);
}

/**
 * Process CSV columns and create custom attributes
 */
async function processCustomAttributes(config, appId, csvFilePath) {
  // Get CSV columns
  const allColumns = getCsvColumnsWithDetails(csvFilePath);
  const columns = allColumns.included;
  const excludedColumns = allColumns.excluded;

  console.log(`   ${style.badge.ok()} CSV parsed successfully`);
  console.log(`   ${style.badge.arrow()} Total columns found: ${style.count(allColumns.total)}`);

  if (excludedColumns.length > 0) {
    console.log(`   ${style.badge.arrow()} Excluded columns ${style.dim('(ent_*)')}: ${style.count(excludedColumns.length)}`);
    excludedColumns.forEach(col => console.log(`     ${style.badge.bullet()} ${style.attr(col)} ${style.dim('(skipped)')}`));
  }

  console.log(`   ${style.badge.arrow()} Columns to process: ${style.count(columns.length)}`);
  if (columns.length > 0) {
    columns.forEach(col => console.log(`     ${style.badge.bullet()} ${style.attr(col)}`));
  }
  console.log('');

  if (columns.length === 0) {
    console.log(`   ${style.info('ℹ')} No columns to process ${style.dim('(all columns start with "ent_")')}`);
    return []; // Return empty array for mapping
  }

  // Get existing schema
  console.log(`   ${style.badge.arrow()} Fetching current app user schema from Okta...`);
  console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('GET /api/v1/meta/schemas/apps/' + appId + '/default')}`);
  const schema = await getAppUserSchema(config, appId);

  const existingAttributes = schema.definitions?.custom?.properties || {};
  const existingAttributeNames = Object.keys(existingAttributes);

  console.log(`   ${style.badge.ok()} Schema retrieved successfully`);
  console.log(`   ${style.badge.arrow()} Existing custom attributes: ${style.count(existingAttributeNames.length)}`);

  if (existingAttributeNames.length > 0) {
    console.log(`   ${style.badge.arrow()} Current attributes:`);
    existingAttributeNames.forEach(attr => console.log(`     ${style.badge.bullet()} ${style.attr(attr)}`));
  }
  console.log('');

  // Determine which attributes need to be created
  const attributesToCreate = columns.filter(col => !existingAttributeNames.includes(col));
  const attributesAlreadyExist = columns.filter(col => existingAttributeNames.includes(col));

  if (attributesAlreadyExist.length > 0) {
    console.log(`   ${style.badge.ok()} ${style.count(attributesAlreadyExist.length)} attribute(s) already exist ${style.dim('(skipping)')}:`);
    attributesAlreadyExist.forEach(attr => console.log(`     ${style.badge.bullet()} ${style.attr(attr)}`));
    console.log('');
  }

  if (attributesToCreate.length === 0) {
    console.log(`   ${style.badge.ok()} ${style.success('All required attributes already exist')}`);
    console.log(`   ${style.badge.arrow()} ${style.dim('No new attributes need to be created')}`);
    return columns; // Return all columns for mapping
  }

  console.log(`   ${style.badge.arrow()} Creating ${style.count(attributesToCreate.length)} new custom attribute(s)...`);
  console.log('');

  let successCount = 0;
  let failureCount = 0;
  const successfullyCreated = [];

  for (const attributeName of attributesToCreate) {
    try {
      console.log(`   ${style.badge.arrow()} Creating attribute: ${style.attr('"' + attributeName + '"')}`);
      console.log(`     ${style.dim('API Call:')} ${style.dim('POST /api/v1/meta/schemas/apps/' + appId + '/default')}`);
      await createCustomAttribute(config, appId, attributeName);
      console.log(`     ${style.badge.ok()} ${style.success('Successfully created')}`);
      successCount++;
      successfullyCreated.push(attributeName);
    } catch (error) {
      console.error(`     ${style.badge.fail()} ${style.error('Failed:')} ${error.message}`);
      failureCount++;
    }
    console.log('');
  }

  console.log(`   📊 ${style.label('Custom Attribute Summary:')}`);
  console.log(`     ${style.badge.bullet()} Total columns in CSV: ${style.count(allColumns.total)}`);
  console.log(`     ${style.badge.bullet()} Already existed: ${style.count(attributesAlreadyExist.length)}`);
  console.log(`     ${style.badge.bullet()} ${style.success('Successfully created:')} ${style.count(successCount)}`);
  if (failureCount > 0) {
    console.log(`     ${style.badge.bullet()} ${style.error('Failed to create:')} ${style.count(failureCount)}`);
  }

  // Return all columns (both newly created and already existing) for mapping
  return columns;
}

/**
 * Ensure all entitlement values from CSV exist in Okta
 * Creates any missing values before user processing
 */
async function ensureEntitlementValues(config, appId, records, entitlementsMap) {
  const newValuesCreated = [];

  // Collect all unique values per entitlement from CSV
  const valuesByEntitlement = {};

  for (const record of records) {
    for (const [key, value] of Object.entries(record)) {
      if (key.startsWith('ent_') && value) {
        const entitlementName = key.substring(4).toLowerCase();
        const entitlement = entitlementsMap[entitlementName];

        if (entitlement && entitlement.id) {
          if (!valuesByEntitlement[entitlementName]) {
            valuesByEntitlement[entitlementName] = new Set();
          }
          const csvValues = value.split(',').map(v => v.trim()).filter(v => v);
          csvValues.forEach(v => valuesByEntitlement[entitlementName].add(v));
        }
      }
    }
  }

  // Check for new values and create them
  for (const [entitlementName, valuesSet] of Object.entries(valuesByEntitlement)) {
    const entitlement = entitlementsMap[entitlementName];
    if (!entitlement || !entitlement.values) continue;

    for (const val of valuesSet) {
      const exists = entitlement.values.some(
        ev => ev.name && ev.name.toLowerCase() === val.toLowerCase()
      );

      if (!exists) {
        try {
          console.log(`   → New entitlement value detected: "${val}" for ${entitlementName}`);
          const newValue = await addEntitlementValue(config, entitlement.id, val, appId);
          if (newValue && newValue.id) {
            console.log(`     ✓ Created: ${val} (${newValue.id})`);
            entitlement.values.push(newValue);
            newValuesCreated.push({ entitlement: entitlementName, value: val });
          }
        } catch (error) {
          console.log(`     ⚠ Failed to create "${val}": ${error.message}`);
        }
      }
    }
  }

  return newValuesCreated;
}

/**
 * Build entitlements array for a user from CSV record
 */
function buildUserEntitlements(record, entitlementsMap) {
  const entitlementsForGrant = {};

  for (const [key, value] of Object.entries(record)) {
    if (key.startsWith('ent_') && value) {
      const entitlementName = key.substring(4);
      const entitlement = entitlementsMap[entitlementName.toLowerCase()];

      if (entitlement && entitlement.id && entitlement.values) {
        const csvValues = [...new Set(value.split(',').map(v => v.trim()).filter(v => v))];

        for (const val of csvValues) {
          const entValue = entitlement.values.find(
            ev => ev.name && ev.name.toLowerCase() === val.toLowerCase()
          );

          if (entValue && entValue.id) {
            if (!entitlementsForGrant[entitlement.id]) {
              entitlementsForGrant[entitlement.id] = {
                id: entitlement.id,
                values: []
              };
            }
            const alreadyAdded = entitlementsForGrant[entitlement.id].values.some(
              v => v.id === entValue.id
            );
            if (!alreadyAdded) {
              entitlementsForGrant[entitlement.id].values.push({
                id: entValue.id,
                name: entValue.name || val,
                description: entValue.description || val,
                label: entValue.name || val
              });
            }
          }
        }
      }
    }
  }

  return Object.values(entitlementsForGrant);
}

/**
 * Sync users from CSV with Okta - handles adds, updates, and deletes
 */
async function syncUsers(config, appId, csvFilePath, resourceId, entitlementsMap) {
  console.log('🔄 SYNC: Checking for changes...');
  console.log('');

  try {
    // Read CSV to get expected state
    const fileContent = fs.readFileSync(csvFilePath, 'utf8');
    const records = parse(fileContent, {
      columns: true,
      skip_empty_lines: true,
      trim: true
    });

    // Build map of expected users from CSV (keyed by username)
    const csvUsers = {};
    const usernameKeys = ['username', 'login', 'email', 'user', 'userid', 'user_id', 'mail'];

    for (const record of records) {
      let username = null;
      for (const key of usernameKeys) {
        const matchingCol = Object.keys(record).find(col => col.toLowerCase() === key);
        if (matchingCol && record[matchingCol]) {
          username = record[matchingCol];
          break;
        }
      }
      if (username) {
        csvUsers[username.toLowerCase()] = record;
      }
    }

    // Ensure all entitlement values from CSV exist (create new ones if needed)
    let entitlementsCreated = 0;
    if (entitlementsMap && Object.keys(entitlementsMap).length > 0) {
      console.log('   → Checking for new entitlement values...');
      const newValues = await ensureEntitlementValues(config, appId, records, entitlementsMap);
      entitlementsCreated = newValues.length;
      if (newValues.length > 0) {
        console.log(`   ✓ Created ${newValues.length} new entitlement value(s):`);
        for (const nv of newValues) {
          console.log(`     • ${nv.entitlement}: "${nv.value}"`);
        }
        console.log('');
      } else {
        console.log('   ✓ All entitlement values already exist');
      }
    }

    // Get current Okta state with retry on rate limit or token expiration
    console.log('   → Fetching current users from Okta...');
    let oktaAppUsers = [];
    let retries = 0;
    while (retries < 3) {
      try {
        oktaAppUsers = await getAppUsers(config, appId);
        break;
      } catch (error) {
        if (error.message.includes('401') && retries < 2) {
          // Token expired - refresh and retry
          retries++;
          console.log(`   ⚠ Token expired, refreshing... (retry ${retries}/3)`);
          clearCachedToken();
          await getAuthHeader(config, true); // Force token refresh
        } else if (error.message.includes('429') && retries < 2) {
          retries++;
          console.log(`   ⚠ Rate limited, waiting 10 seconds (retry ${retries}/3)...`);
          await new Promise(resolve => setTimeout(resolve, 10000));
        } else {
          throw error;
        }
      }
    }
    console.log(`   ✓ Found ${oktaAppUsers.length} user(s) currently assigned to app`);
    console.log(`   ✓ CSV contains ${Object.keys(csvUsers).length} user(s)`);
    console.log('');

    // Build map of Okta users (keyed by login/email)
    const oktaUsers = {};
    for (const appUser of oktaAppUsers) {
      const login = appUser.credentials?.userName || appUser.profile?.email;
      if (login) {
        oktaUsers[login.toLowerCase()] = appUser;
      }
    }

    // Identify changes
    const toAdd = [];
    const toUpdate = [];
    const toRemove = [];

    // Check for new users (in CSV but not in Okta)
    for (const [username, record] of Object.entries(csvUsers)) {
      if (!oktaUsers[username]) {
        toAdd.push({ username, record });
      } else {
        // Check if user needs update (compare profiles)
        toUpdate.push({ username, record, oktaUser: oktaUsers[username] });
      }
    }

    // Check for removed users (in Okta but not in CSV)
    for (const [username, oktaUser] of Object.entries(oktaUsers)) {
      if (!csvUsers[username]) {
        toRemove.push({ username, oktaUser });
      }
    }

    console.log('   📊 Changes detected:');
    console.log(`     • New users to add: ${toAdd.length}`);
    console.log(`     • Users to update: ${toUpdate.length}`);
    console.log(`     • Users to remove: ${toRemove.length}`);
    console.log('');

    let added = 0, updated = 0, removed = 0, failed = 0;

    // Process removals first
    if (toRemove.length > 0) {
      console.log('   🗑️  Removing users no longer in CSV...');
      for (const { username, oktaUser } of toRemove) {
        try {
          console.log(`     → Removing ${username}...`);

          // Revoke grants first
          const grants = await getUserGrants(config, appId, oktaUser.id);
          for (const grant of grants) {
            try {
              await revokeGrant(config, grant.id);
            } catch (e) {
              // Continue even if grant revocation fails
            }
          }

          // Unassign from app
          await unassignUserFromApp(config, appId, oktaUser.id);
          console.log(`     ✓ ${username} removed`);
          removed++;
        } catch (error) {
          console.log(`     ✗ Failed to remove ${username}: ${error.message}`);
          failed++;
        }
      }
      console.log('');
    }

    // Process additions
    if (toAdd.length > 0) {
      console.log('   ➕ Adding new users from CSV...');
      for (const { username, record } of toAdd) {
        try {
          console.log(`     → Adding ${username}...`);

          // Build user profile
          const userProfile = { login: username, email: username };
          for (const [csvColumn, value] of Object.entries(record)) {
            if (!value || csvColumn.startsWith('ent_')) continue;
            const oktaAttribute = findMatchingOktaAttribute(csvColumn);
            if (oktaAttribute) {
              userProfile[oktaAttribute] = value;
            }
          }
          if (!userProfile.firstName) userProfile.firstName = '';
          if (!userProfile.lastName) userProfile.lastName = '';

          // Find or create user
          let user = await findUser(config, username);
          if (!user) {
            const randomPassword = generateSecurePassword();
            user = await createUser(config, {
              profile: userProfile,
              credentials: { password: { value: randomPassword } }
            });
          }

          // Build app user profile (exclude identity and entitlement columns)
          const appUserProfile = {};
          const identityColumns = [
            'username', 'login', 'email', 'user', 'userid', 'user_id', 'mail',
            'firstname', 'first_name', 'lastname', 'last_name', 'displayname',
            'display_name', 'name', 'fullname', 'full_name'
          ];
          for (const [key, value] of Object.entries(record)) {
            if (!value) continue;
            if (key.startsWith('ent_')) continue;
            if (identityColumns.includes(key.toLowerCase())) continue;
            appUserProfile[key] = value;
          }

          // Assign to app
          await assignUserToApp(config, appId, user.id, appUserProfile);

          // Create entitlement grants
          if (resourceId && Object.keys(entitlementsMap).length > 0) {
            const entitlementsArray = buildUserEntitlements(record, entitlementsMap);
            if (entitlementsArray.length > 0) {
              await createEntitlementGrant(config, appId, user.id, entitlementsArray);
            }
          }

          console.log(`     ✓ ${username} added with entitlements`);
          added++;
        } catch (error) {
          console.log(`     ✗ Failed to add ${username}: ${error.message}`);
          failed++;
        }
      }
      console.log('');
    }

    // Process updates (check for attribute/entitlement changes)
    if (toUpdate.length > 0) {
      console.log('   🔄 Checking for updates...');
      let updatesNeeded = 0;
      let entitlementsUpdated = 0;
      let checkedCount = 0;

      for (const { username, record, oktaUser } of toUpdate) {
        try {
          // Build expected app profile
          const expectedProfile = {};
          for (const [key, value] of Object.entries(record)) {
            if (value) expectedProfile[key] = value;
          }

          // Compare with current profile - check ALL fields for changes
          const currentProfile = oktaUser.profile || {};
          let profileChanged = false;
          const changedFields = [];

          for (const [key, value] of Object.entries(expectedProfile)) {
            if (currentProfile[key] !== value) {
              profileChanged = true;
              changedFields.push(key);
            }
          }

          // Only make API calls if something actually changed
          if (profileChanged) {
            console.log(`     → Updating ${username} (changed: ${changedFields.slice(0, 3).join(', ')}${changedFields.length > 3 ? '...' : ''})...`);
            await updateAppUserProfile(config, appId, oktaUser.id, expectedProfile);

            // Also update entitlements for this user
            if (resourceId && Object.keys(entitlementsMap).length > 0) {
              const expectedEntitlements = buildUserEntitlements(record, entitlementsMap);
              if (expectedEntitlements.length > 0) {
                // Revoke existing grants first
                const currentGrants = await getUserGrants(config, appId, oktaUser.id);
                for (const grant of currentGrants) {
                  try {
                    await revokeGrant(config, grant.id);
                  } catch (e) {
                    // Continue
                  }
                }
                // Create new grants
                await createEntitlementGrant(config, appId, oktaUser.id, expectedEntitlements);
                entitlementsUpdated++;
              }
            }

            console.log(`     ✓ ${username} updated`);
            updatesNeeded++;
            updated++;

            // Rate limiting - pause after every 10 updates
            if (updatesNeeded % 10 === 0) {
              console.log(`     ⏸  Pausing to avoid rate limits...`);
              await new Promise(resolve => setTimeout(resolve, 2000));
            }
          }

          checkedCount++;
        } catch (error) {
          console.log(`     ✗ Failed to update ${username}: ${error.message}`);
          failed++;
          // Add delay on error to avoid cascading rate limits
          if (error.message.includes('429')) {
            console.log(`     ⏸  Rate limited, waiting 5 seconds...`);
            await new Promise(resolve => setTimeout(resolve, 5000));
          }
        }
      }

      if (updatesNeeded === 0) {
        console.log(`     ✓ No changes detected (checked ${checkedCount} users)`);
      } else {
        console.log(`     ✓ Updated ${updatesNeeded} user(s), ${entitlementsUpdated} entitlement grant(s)`);
      }
      console.log('');
    }

    // Print verbose sync results
    const syncTime = new Date().toLocaleTimeString();
    console.log(`   ${colors.cyan}${'─'.repeat(50)}${colors.reset}`);
    console.log(`   📊 ${style.label('SYNC RESULTS')} ${style.dim('[' + syncTime + ']')}`);
    console.log(`   ${colors.cyan}${'─'.repeat(50)}${colors.reset}`);
    console.log(`     Entitlements Created: ${style.count(entitlementsCreated)}`);
    console.log(`     Users Added:          ${style.count(added)}`);
    console.log(`     Users Updated:        ${style.count(updated)}`);
    console.log(`     Users Removed:        ${style.count(removed)}`);
    if (failed > 0) {
      console.log(`     ${style.error('Failed:')}               ${style.count(failed)}`);
    }
    console.log(`     Total in Okta:        ${style.count(oktaAppUsers.length)}`);
    console.log(`     Total in CSV:         ${style.count(Object.keys(csvUsers).length)}`);
    console.log(`   ${colors.cyan}${'─'.repeat(50)}${colors.reset}`);
    console.log('');

    // Role Mining in sync mode (if enabled)
    if (config.roleMining?.syncMode === 'every') {
      console.log(`   ${style.badge.arrow()} Running role mining analysis...`);
      try {
        const { runRoleMining } = await import('./roleMining.js');
        await runRoleMining(config, appId, resourceId, entitlementsMap, csvFilePath);
      } catch (error) {
        console.log(`   ${style.badge.warn()} ${style.warning('Role mining error:')} ${error.message}`);
      }
    }

    return { added, updated, removed, failed, entitlementsCreated };
  } catch (error) {
    console.log(`   ${style.badge.fail()} ${style.error('Sync error:')} ${error.message}`);
    console.log('');
    return { added: 0, updated: 0, removed: 0, failed: 1 };
  }
}

/**
 * Run in sync mode - periodically check for changes
 */
async function runSyncMode(config, app, csvFilePath, resourceId, entitlementsMap) {
  const intervalMinutes = config.syncInterval || 5;
  const intervalMs = intervalMinutes * 60 * 1000;

  console.log('');
  console.log(`${colors.brightMagenta}${'='.repeat(70)}${colors.reset}`);
  console.log(`${colors.brightMagenta}${colors.bold}🔁 SYNC MODE ENABLED${colors.reset}`);
  console.log(`${colors.brightMagenta}${'='.repeat(70)}${colors.reset}`);
  console.log(`   Checking for changes every ${style.count(intervalMinutes)} minute(s)`);
  console.log(`   ${style.dim('Press Ctrl+C to stop')}`);
  console.log('');

  // Run initial sync
  await syncUsers(config, app.id, csvFilePath, resourceId, entitlementsMap);

  // Schedule periodic syncs
  const syncLoop = async () => {
    const now = new Date().toLocaleTimeString();
    console.log(`⏰ ${style.dim('[' + now + ']')} Running scheduled sync...`);
    console.log('');
    await syncUsers(config, app.id, csvFilePath, resourceId, entitlementsMap);
    console.log(`   Next sync in ${style.count(intervalMinutes)} minute(s)`);
    console.log('');
  };

  setInterval(syncLoop, intervalMs);

  // Keep process running
  process.on('SIGINT', () => {
    console.log('');
    console.log('👋 Sync mode stopped');
    process.exit(0);
  });
}

function printBanner() {
  const banner = `
${colors.brightCyan}     ██████╗ ██╗  ██╗████████╗ █████╗
    ██╔═══██╗██║ ██╔╝╚══██╔══╝██╔══██╗
    ██║   ██║█████╔╝    ██║   ███████║
    ██║   ██║██╔═██╗    ██║   ██╔══██║
    ╚██████╔╝██║  ██╗   ██║   ██║  ██║
     ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝${colors.reset}

    ${colors.bold}Disconnected App Governance Connector${colors.reset}
`;
  console.log(banner);
}

async function main() {
  try {
    printBanner();
    console.log('');

    // Get configuration (from file or prompt user)
    console.log(`📋 ${style.step('STEP 1: Loading Configuration')}`);
    console.log(`   ${style.badge.arrow()} Checking for existing configuration file ${style.dim('(config.json)')}...`);
    let config = await getConfig();
    console.log(`   ${style.badge.ok()} Configuration loaded successfully`);
    console.log(`   ${style.badge.ok()} Connected to Okta tenant: ${style.url(config.oktaDomain)}`);
    console.log('');

    // Find CSV files in current directory
    console.log(`📂 ${style.step('STEP 2: CSV File Discovery')}`);
    console.log(`   ${style.badge.arrow()} Scanning current directory for .csv files...`);
    const csvFiles = findCsvFiles();

    if (csvFiles.length === 0) {
      console.log(`   ${style.badge.fail()} ${style.error('No CSV files found in the current directory.')}`);
      console.log('');
      console.log(`💡 ${style.warning('TIP:')} Place a CSV file in the current directory and run again.`);
      console.log('   The CSV filename will be used as the application name in Okta.');
      process.exit(0);
    }

    // Determine which CSV file to process
    let selectedCsvFile;

    if (csvFiles.length === 1) {
      // Only one CSV file, use it automatically
      selectedCsvFile = csvFiles[0];
      console.log(`   ${style.badge.ok()} Found ${style.count('1')} CSV file: ${style.name(selectedCsvFile)}`);
      console.log(`   ${style.badge.arrow()} Automatically selected for processing`);
    } else {
      // Multiple CSV files found
      console.log(`   ${style.badge.ok()} Found ${style.count(csvFiles.length)} CSV files:`);
      csvFiles.forEach(file => console.log(`     ${style.badge.bullet()} ${style.name(file)}`));
      console.log('');

      // Check if there's a saved selection
      if (config.selectedCsvFile && csvFiles.includes(config.selectedCsvFile)) {
        selectedCsvFile = config.selectedCsvFile;
        console.log(`   ${style.badge.arrow()} Using previously selected file from configuration`);
        console.log(`   ${style.badge.ok()} Selected: ${style.name(selectedCsvFile)}`);
        console.log('');
        console.log(`   💡 ${style.dim('TIP: To change selection, delete config.json and run again')}`);
      } else {
        console.log(`   ${style.badge.arrow()} No saved selection found, prompting for user input...`);
        selectedCsvFile = await selectCsvFile(csvFiles);

        // Save selection to config
        config.selectedCsvFile = selectedCsvFile;
        await saveConfig(config);
        console.log(`   ${style.badge.ok()} Selection saved to configuration file`);
      }
    }
    console.log('');

    // Process the selected CSV file
    const appName = path.basename(selectedCsvFile, '.csv');
    console.log(`🔧 ${style.step('STEP 3: Application Processing')}`);
    console.log(`   ${style.badge.arrow()} CSV File: ${style.name(selectedCsvFile)}`);
    console.log(`   ${style.badge.arrow()} Application Name: ${style.name('"' + appName + '"')}`);
    console.log('');

    // Check if app exists
    console.log(`   ${style.badge.arrow()} Querying Okta API to check if application exists...`);
    console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('GET /api/v1/apps?q=' + encodeURIComponent(appName))}`);
    const existingApp = await findAppByName(config, appName);

    let app;
    if (existingApp) {
      console.log(`   ${style.badge.ok()} ${style.success('Application found in Okta!')}`);
      console.log('');
      console.log(`   📊 ${style.label('Application Details:')}`);
      console.log(`     ${style.badge.bullet()} App ID: ${style.id(existingApp.id)}`);
      console.log(`     ${style.badge.bullet()} Status: ${style.value(existingApp.status)}`);
      console.log(`     ${style.badge.bullet()} Sign-On Mode: ${style.attr(existingApp.signOnMode)}`);
      console.log('');
      console.log(`   ${style.badge.arrow()} Skipping application creation ${style.dim('(already exists)')}`);
      app = existingApp;
    } else {
      console.log(`   ${style.info('ℹ')} Application does not exist in Okta`);
      console.log(`   ${style.badge.arrow()} Preparing SAML 2.0 application definition...`);
      console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('POST /api/v1/apps')}`);
      console.log('');
      const newApp = await createSamlApp(config, appName);
      console.log(`   ${style.badge.ok()} ${style.success('Application created successfully!')}`);
      console.log('');
      console.log(`   📊 ${style.label('New Application Details:')}`);
      console.log(`     ${style.badge.bullet()} App ID: ${style.id(newApp.id)}`);
      console.log(`     ${style.badge.bullet()} Name: ${style.name(newApp.label)}`);
      console.log(`     ${style.badge.bullet()} Status: ${style.value(newApp.status)}`);
      console.log(`     ${style.badge.bullet()} Sign-On Mode: ${style.attr(newApp.signOnMode)}`);
      console.log('');
      console.log(`   💡 ${style.warning('NOTE:')} SAML settings use placeholder values.`);
      console.log(`   ${style.dim('Update SSO URLs and audience in Okta Admin Console.')}`);
      app = newApp;
    }
    console.log('');

    // Register app with governance and enable entitlement management
    console.log(`🔐 ${style.step('STEP 4: Entitlement Management Configuration')}`);
    let governanceResourceId = null;

    // First check if resource already exists
    console.log(`   ${style.badge.arrow()} Checking if app is registered in Governance...`);
    console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('GET /governance/api/v1/resources?filter=source.id eq "' + app.id + '"')}`);
    governanceResourceId = await getGovernanceResourceId(config, app.id);

    if (!governanceResourceId) {
      // Try to opt-in the app to governance / enable entitlement management
      console.log(`   ${style.badge.arrow()} App not registered in Governance, enabling entitlement management...`);
      try {
        const resource = await registerGovernanceResource(config, app.id, app.label);
        governanceResourceId = resource.id;
        console.log(`   ${style.badge.ok()} Governance resource ID: ${style.id(governanceResourceId)}`);
      } catch (error) {
        console.log(`   ${style.badge.warn()} ${style.warning('Could not enable entitlement management:')} ${error.message}`);
        console.log(`   ${style.badge.arrow()} ${style.dim('This feature requires Okta Identity Governance (OIG) license')}`);
        console.log(`   ${style.badge.arrow()} ${style.dim('Entitlements may need to be enabled manually in Admin Console')}`);
        console.log('');
      }
    } else {
      console.log(`   ${style.badge.ok()} App already registered in Governance: ${style.id(governanceResourceId)}`);
    }

    // Enable entitlement management if we have a resource ID
    if (governanceResourceId) {
      console.log(`   ${style.badge.arrow()} Enabling entitlement management...`);
      console.log(`   ${style.badge.arrow()} ${style.dim('API Call:')} ${style.dim('PUT /governance/api/v1/resources/' + governanceResourceId + '/entitlement-management')}`);
      try {
        await enableEntitlementManagement(config, governanceResourceId);
        console.log(`   ${style.badge.ok()} ${style.success('Entitlement management enabled successfully')}`);
        console.log(`   ${style.badge.arrow()} App is now ready for entitlement creation`);
      } catch (error) {
        console.log(`   ${style.badge.warn()} ${style.warning('Could not enable entitlement management:')} ${error.message}`);
        console.log(`   ${style.badge.arrow()} ${style.dim('Entitlement management may already be enabled')}`);
      }
    }
    console.log('');

    // Process custom attributes from CSV columns
    console.log(`🏷️  ${style.step('STEP 5: Custom Attribute Management')}`);
    console.log(`   ${style.badge.arrow()} Reading CSV column headers...`);
    console.log(`   ${style.badge.arrow()} Filtering out enterprise columns ${style.dim('(starting with "ent_")')}...`);
    const attributes = await processCustomAttributes(config, app.id, selectedCsvFile);

    // Process attribute mappings to Okta user profile
    if (attributes && attributes.length > 0) {
      await processAttributeMappings(config, app.id, attributes);
    }

    // Process entitlements from CSV
    const entitlementsMap = await processEntitlements(config, app.id, selectedCsvFile, governanceResourceId);

    // Process users from CSV - create/update and assign to app with entitlements
    await processUsers(config, app.id, selectedCsvFile, governanceResourceId, entitlementsMap);

    // STEP 9: Role Mining & Bundle Creation
    if (config.roleMining?.enabled !== false) {
      try {
        const { runRoleMining } = await import('./roleMining.js');
        await runRoleMining(config, app.id, governanceResourceId, entitlementsMap, selectedCsvFile);
      } catch (error) {
        console.log('');
        console.log(`${style.badge.warn()} ${style.warning('Role mining encountered an error but continuing:')}`);
        console.log(`   ${style.dim(error.message)}`);
      }
    }

    console.log('');
    console.log(`${colors.green}${'='.repeat(70)}${colors.reset}`);
    console.log(`${colors.green}${colors.bold}✅ Initial Processing Complete!${colors.reset}`);
    console.log(`${colors.green}${'='.repeat(70)}${colors.reset}`);
    console.log('');

    // Check if sync mode is enabled
    if (config.syncInterval && config.syncInterval > 0) {
      // Enter sync mode - will run indefinitely
      await runSyncMode(config, app, selectedCsvFile, governanceResourceId, entitlementsMap);
    } else {
      // One-time run - show next steps and exit
      console.log(`📍 ${style.label('Next Steps:')}`);
      console.log(`   ${style.count('1.')} Login to Okta Admin Console`);
      console.log(`   ${style.count('2.')} Navigate to ${style.dim('Applications →')} ${style.name(appName)}`);
      console.log(`   ${style.count('3.')} Review users assigned to the app under ${style.attr('Assignments')} tab`);
      console.log(`   ${style.count('4.')} Check entitlements under ${style.attr('Identity Governance → Resources')}`);
      console.log('');
      console.log(`💡 ${style.warning('TIP:')} To enable automatic sync mode, add ${style.value('"syncInterval": 5')} to config.json`);
      console.log(`   ${style.dim('This will check for CSV changes every 5 minutes.')}`);
      console.log('');
    }

  } catch (error) {
    console.log('');
    console.error('❌ ERROR:', error.message);
    console.log('');

    // Check if this is an authentication configuration error - offer to reconfigure
    if (error.message.includes('Authentication incomplete') ||
        error.message.includes('OAuth configuration incomplete') ||
        error.message.includes('missing authentication credentials') ||
        error.message.includes('No authentication credentials found')) {
      console.log('💡 This error indicates missing or incomplete authentication in your configuration.');
      console.log('   API Token (SSWS) is recommended for full Okta API compatibility.');
      console.log('');

      try {
        // Reconfigure OAuth credentials
        const updatedConfig = await reconfigureOAuthCredentials();

        console.log('');
        console.log('✓ Configuration updated. Restarting...');
        console.log('');

        // Restart main with updated config
        return main();
      } catch (configError) {
        console.error('Failed to reconfigure:', configError.message);
        process.exit(1);
      }
    }

    console.log('💡 Troubleshooting:');
    console.log('   • Check your Okta domain and API token are correct');
    console.log('   • Verify API token has application management permissions');
    console.log('   • Ensure CSV file is properly formatted');
    console.log('   • Check network connectivity to Okta');
    console.log('');
    process.exit(1);
  }
}

main();
