import okta from '@okta/okta-sdk-nodejs';
const { Client } = okta;
import { getConfig, saveConfig, selectCsvFile, getAccessToken, getAccessTokenDeviceFlow } from './config.js';
import fs from 'fs';
import path from 'path';
import { parse } from 'csv-parse/sync';

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
 * Supports Device Flow, Client Credentials, and SSWS token
 * Automatically refreshes expired OAuth tokens
 */
async function getAuthHeader(config, forceRefresh = false) {
  if (config.clientId) {
    // Use OAuth - get or reuse cached token, refresh if expired
    if (!cachedAccessToken || isTokenExpired() || forceRefresh) {
      if (forceRefresh && cachedAccessToken) {
        console.log('   → Token expired or invalid, refreshing...');
      }
      if (config.authFlow === 'device') {
        // Device flow - user authenticates in browser
        cachedAccessToken = await getAccessTokenDeviceFlow(config);
        // Device flow tokens typically last 1 hour
        tokenExpiresAt = Date.now() + (60 * 60 * 1000);
      } else if (config.clientSecret || config.privateKey || config.privateKeyPath) {
        // Client credentials flow (with client_secret or private_key_jwt)
        cachedAccessToken = await getAccessToken(config);
        // Client credentials tokens typically last 1 hour (3600 seconds)
        tokenExpiresAt = Date.now() + (60 * 60 * 1000);
      } else {
        throw new Error('OAuth configuration incomplete: missing authentication credentials (clientSecret, privateKey, or privateKeyPath)');
      }
      if (forceRefresh) {
        console.log('   ✓ Token refreshed successfully');
      }
    }
    return `Bearer ${cachedAccessToken}`;
  } else if (config.apiToken) {
    // Fallback to SSWS token (legacy)
    return `SSWS ${config.apiToken}`;
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

    // Include ALL columns (including ent_* columns as custom attributes)
    return {
      total: allColumns.length,
      included: allColumns,  // All columns
      excluded: []           // No longer excluding ent_* columns
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

    // Use SSWS token for governance opt-in endpoint (testing)
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
  console.log('📦 STEP 7: Entitlement Catalog & Creation');
  console.log('   → Parsing CSV file for entitlement columns (ent_*)...');

  const catalog = generateEntitlementCatalog(csvFilePath);
  const entColumns = Object.keys(catalog);

  if (entColumns.length === 0) {
    console.log('   ℹ No entitlement columns found in CSV');
    console.log('   → Entitlement columns must start with "ent_" prefix');
    console.log('');
    return;
  }

  console.log(`   ✓ Found ${entColumns.length} entitlement column(s):`);
  let totalEntitlements = 0;
  for (const [column, values] of Object.entries(catalog)) {
    console.log(`     • ${column}: ${values.length} unique value(s)`);
    totalEntitlements += values.length;
  }
  console.log(`   → Total unique entitlements to create: ${totalEntitlements}`);
  console.log('');

  // Use existing resource ID if provided, otherwise fetch it
  let resourceId = existingResourceId;

  if (!resourceId) {
    console.log('   → Fetching governance resource ID for app...');
    console.log(`   → API Call: GET /governance/api/v1/resources?filter=source.id eq "${appId}"`);
    resourceId = await getGovernanceResourceId(config, appId);
  } else {
    console.log(`   → Using governance resource ID from Step 4: ${resourceId}`);
  }

  if (!resourceId) {
    console.log('   ⚠ Could not find governance resource for this app');
    console.log('   → Entitlement management may not be enabled yet');
    console.log('   → Try enabling it in Okta Admin Console: Identity Governance → Resources');
    console.log('');
    console.log('   📋 Entitlement Catalog Summary:');
    for (const [column, values] of Object.entries(catalog)) {
      const attributeName = column.substring(4); // Remove 'ent_' prefix
      console.log(`     • ${attributeName}: ${values.join(', ')}`);
    }
    console.log('');
    return;
  }

  console.log(`   ✓ Governance resource found: ${resourceId}`);
  console.log('');

  // Check existing entitlements
  console.log('   → Fetching existing entitlements...');
  console.log(`   → API Call: GET /governance/api/v1/resources/${resourceId}/entitlements`);

  let existingEntitlements = [];
  try {
    existingEntitlements = await getAppEntitlements(config, resourceId, appId);
  } catch (error) {
    if (error.message.includes('405')) {
      console.log(`   ⚠ Cannot fetch existing entitlements (HTTP 405)`);
      console.log('   → Assuming no existing entitlements, will attempt to create all');
      console.log('');
    } else {
      console.log(`   ⚠ Could not fetch entitlements from governance API: ${error.message}`);
      console.log('   → Proceeding to create entitlements');
      console.log('');
    }
    // Continue with empty array - we'll try to create all entitlements
    existingEntitlements = [];
  }

  if (existingEntitlements === null) {
    existingEntitlements = [];
  }

  console.log(`   ✓ Found ${existingEntitlements.length} existing entitlements`);
  console.log('');

  // Create entitlements from catalog
  console.log('   → Creating entitlements from CSV catalog...');
  console.log('');

  let created = 0;
  let skipped = 0;
  let failed = 0;
  const createdEntitlements = {}; // Track created entitlements for later use

  // Create ONE entitlement per column (attribute) with all values
  for (const [column, values] of Object.entries(catalog)) {
    const attributeName = column.substring(4); // Remove 'ent_' prefix
    console.log(`   → Creating ${attributeName} entitlement with ${values.length} value(s):`);

    try {
      // Check if entitlement already exists
      const existingEnt = existingEntitlements.find(ent =>
        ent.name && ent.name.toLowerCase() === attributeName.toLowerCase()
      );

      if (existingEnt) {
        console.log(`     ⊘ ${attributeName} entitlement already exists (skipped)`);
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

      console.log(`     → Values: ${values.join(', ')}`);
      const newEntitlement = await createEntitlement(config, resourceId, entitlementData);
      console.log(`     ✓ ${attributeName} entitlement created with ${values.length} value(s)`);

      // Store the created entitlement for later use
      if (newEntitlement && newEntitlement.id) {
        createdEntitlements[attributeName.toLowerCase()] = newEntitlement;
      }
      created++;
    } catch (error) {
      // Check if error is because entitlement already exists
      if (error.message.includes('needs to be unique')) {
        console.log(`     ⊘ ${attributeName} entitlement already exists, fetching...`);
        try {
          const existingEnt = await getEntitlementByName(config, appId, attributeName);
          if (existingEnt && existingEnt.id) {
            console.log(`     ✓ Found existing ${attributeName} entitlement (${existingEnt.id})`);
            createdEntitlements[attributeName.toLowerCase()] = existingEnt;
            skipped++;
          } else {
            console.log(`     ⚠ Could not fetch existing ${attributeName} entitlement`);
            failed++;
          }
        } catch (fetchError) {
          console.log(`     ⚠ Error fetching existing entitlement: ${fetchError.message}`);
          failed++;
        }
      } else {
        console.log(`     ✗ ${attributeName} failed: ${error.message}`);
        failed++;
      }
    }
    console.log('');
  }

  console.log('   📊 Entitlement Creation Summary:');
  console.log(`     • Total entitlement columns: ${Object.keys(catalog).length}`);
  console.log(`     • Successfully created: ${created}`);
  console.log(`     • Already existed: ${skipped}`);
  if (failed > 0) {
    console.log(`     • Failed: ${failed}`);
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
  console.log('👥 STEP 8: User Provisioning');
  console.log('   → Reading user data from CSV...');

  try {
    const fileContent = fs.readFileSync(csvFilePath, 'utf8');
    const records = parse(fileContent, {
      columns: true,
      skip_empty_lines: true,
      trim: true
    });

    console.log(`   ✓ Found ${records.length} user(s) in CSV`);
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
        console.log(`   ⚠ Skipping row - no username/email column found (tried: ${usernameKeys.join(', ')})`);
        failed++;
        continue;
      }

      // Declare variables outside try block so they're accessible in catch for retry
      let userId;
      let appUserProfile;

      try {
        console.log(`   → Processing user ${i + 1}/${records.length}: ${username}`);

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
          console.log(`     → User exists (${existingUser.id}), updating...`);
          await updateUser(config, existingUser.id, { profile: userProfile });
          userId = existingUser.id;
          updated++;
        } else {
          console.log(`     → User does not exist, creating...`);
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
          console.log(`     ✓ User created (${userId}) - password reset required on first login`);
        }

        // Build app user profile with custom attributes INCLUDING entitlements
        appUserProfile = {};

        // Add ALL columns as app user attributes (including ent_* entitlement columns)
        for (const [key, value] of Object.entries(record)) {
          if (value) {
            appUserProfile[key] = value;
          }
        }

        // Assign user to app with ALL attributes (including ent_* entitlements)
        console.log(`     → Assigning user to app...`);
        await assignUserToApp(config, appId, userId, appUserProfile);
        console.log(`     ✓ User assigned to app with attributes`);
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
                      console.log(`     → New entitlement value detected: "${val}" for ${entitlementName}`);
                      console.log(`       Creating new value in Okta...`);
                      const newValue = await addEntitlementValue(config, entitlement.id, val, appId);
                      if (newValue && newValue.id) {
                        console.log(`       ✓ Created new entitlement value: ${val} (${newValue.id})`);
                        // Add to local cache so we don't try to create again
                        entitlement.values.push(newValue);
                        entValue = newValue;
                      } else {
                        console.log(`       ⚠ Could not create entitlement value: ${val}`);
                        continue;
                      }
                    } catch (createError) {
                      console.log(`       ⚠ Failed to create entitlement value: ${createError.message}`);
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
              console.log(`     → Creating governance grant with ${entitlementsArray.length} entitlement(s)...`);

              // Debug: log the payload for first user
              if (i === 0) {
                console.log(`     → Debug payload:`, JSON.stringify({
                  grantType: "CUSTOM",
                  targetPrincipal: { externalId: userId, type: "OKTA_USER" },
                  actor: "ADMIN",
                  target: { externalId: appId, type: "APPLICATION" },
                  entitlements: entitlementsArray
                }, null, 2).substring(0, 800));
              }

              await createEntitlementGrant(config, appId, userId, entitlementsArray);
              console.log(`     ✓ Governance grant created`);
              grantsCreated++;
            } catch (error) {
              console.log(`     ⚠ Grant creation failed: ${error.message}`);
              // Don't fail the whole user - they're still assigned to the app
            }
          }
        }

        console.log('');

        // Add small delay to avoid rate limits (every 10 users)
        if ((i + 1) % 10 === 0 && i + 1 < records.length) {
          console.log(`   ⏸  Pausing briefly to avoid rate limits... (${i + 1}/${records.length} processed)`);
          await new Promise(resolve => setTimeout(resolve, 2000));
          console.log('');
        }
      } catch (error) {
        if (error.message.includes('429')) {
          console.log(`     ⚠ Rate limit hit, waiting 5 seconds...`);
          await new Promise(resolve => setTimeout(resolve, 5000));
          // Retry once
          try {
            await assignUserToApp(config, appId, userId, appUserProfile);
            console.log(`     ✓ User assigned to app with attributes (retry succeeded)`);
            assigned++;
          } catch (retryError) {
            console.log(`     ✗ Failed after retry: ${retryError.message}`);
            failed++;
          }
        } else {
          console.log(`     ✗ Failed: ${error.message}`);
          failed++;
        }
        console.log('');
      }
    }

    console.log('   📊 User Provisioning Summary:');
    console.log(`     • Total users in CSV: ${records.length}`);
    console.log(`     • Created: ${created}`);
    console.log(`     • Updated: ${updated}`);
    console.log(`     • Assigned to app: ${assigned}`);
    if (grantsCreated > 0) {
      console.log(`     • Governance grants created: ${grantsCreated}`);
    }
    if (failed > 0) {
      console.log(`     • Failed: ${failed}`);
    }
    console.log('');

  } catch (error) {
    console.log(`   ✗ Error processing users: ${error.message}`);
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
  console.log('🔗 STEP 6: Profile Attribute Mapping');
  console.log('   → Analyzing custom attributes for Okta user profile mappings...');
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

  console.log(`   → Matched attributes: ${matchedAttributes.length}`);
  if (matchedAttributes.length > 0) {
    matchedAttributes.forEach(match => {
      console.log(`     • ${match.customAttribute} → user.${match.oktaAttribute}`);
    });
  }
  console.log('');

  if (unmatchedAttributes.length > 0) {
    console.log(`   → Unmatched attributes (no standard Okta field): ${unmatchedAttributes.length}`);
    unmatchedAttributes.forEach(attr => {
      console.log(`     • ${attr} (will remain as custom attribute only)`);
    });
    console.log('');
  }

  if (matchedAttributes.length === 0) {
    console.log('   ℹ No attributes matched Okta user profile fields');
    console.log('   → Skipping profile mapping');
    return;
  }

  // Get the profile mapping
  console.log('   → Fetching profile mapping configuration...');
  console.log(`   → API Call: GET /api/v1/mappings?sourceId=${appId}`);
  const profileMapping = await getProfileMapping(config, appId);

  if (!profileMapping) {
    console.log('   ✗ Profile mapping not found for this application');
    console.log('   → This may happen if the app was just created');
    console.log('   → Mappings can be configured manually in Okta Admin Console');
    return;
  }

  console.log(`   ✓ Profile mapping found (ID: ${profileMapping.id})`);
  console.log('');

  // Build mapping properties
  const currentProperties = profileMapping.properties || {};
  let mappingsAdded = 0;
  let mappingsSkipped = 0;

  console.log('   → Creating attribute mappings...');
  console.log('');

  for (const match of matchedAttributes) {
    const mappingKey = match.oktaAttribute;

    // Check if mapping already exists
    if (currentProperties[mappingKey]) {
      console.log(`   → Mapping for ${match.customAttribute}:`);
      console.log(`     ℹ Already exists: user.${mappingKey}`);
      mappingsSkipped++;
    } else {
      console.log(`   → Mapping for ${match.customAttribute}:`);
      console.log(`     ✓ Creating: appuser.${match.customAttribute} → user.${mappingKey}`);

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
    console.log(`   → Updating profile mapping with ${mappingsAdded} new mapping(s)...`);
    console.log(`   → API Call: POST /api/v1/mappings/${profileMapping.id}`);

    const updatedMapping = {
      properties: currentProperties
    };

    await updateProfileMapping(config, profileMapping.id, updatedMapping);
    console.log('   ✓ Profile mappings updated successfully');
  } else {
    console.log('   ℹ All matching attributes already have mappings');
  }

  console.log('');
  console.log('   📊 Mapping Summary:');
  console.log(`     • Total attributes analyzed: ${createdAttributes.length}`);
  console.log(`     • Matched to Okta fields: ${matchedAttributes.length}`);
  console.log(`     • Mappings created: ${mappingsAdded}`);
  console.log(`     • Mappings already existed: ${mappingsSkipped}`);
  console.log(`     • Unmatched attributes: ${unmatchedAttributes.length}`);
}

/**
 * Process CSV columns and create custom attributes
 */
async function processCustomAttributes(config, appId, csvFilePath) {
  // Get CSV columns
  const allColumns = getCsvColumnsWithDetails(csvFilePath);
  const columns = allColumns.included;
  const excludedColumns = allColumns.excluded;

  console.log(`   ✓ CSV parsed successfully`);
  console.log(`   → Total columns found: ${allColumns.total}`);

  if (excludedColumns.length > 0) {
    console.log(`   → Excluded columns (ent_*): ${excludedColumns.length}`);
    excludedColumns.forEach(col => console.log(`     • ${col} (skipped)`));
  }

  console.log(`   → Columns to process: ${columns.length}`);
  if (columns.length > 0) {
    columns.forEach(col => console.log(`     • ${col}`));
  }
  console.log('');

  if (columns.length === 0) {
    console.log('   ℹ No columns to process (all columns start with "ent_")');
    return []; // Return empty array for mapping
  }

  // Get existing schema
  console.log('   → Fetching current app user schema from Okta...');
  console.log(`   → API Call: GET /api/v1/meta/schemas/apps/${appId}/default`);
  const schema = await getAppUserSchema(config, appId);

  const existingAttributes = schema.definitions?.custom?.properties || {};
  const existingAttributeNames = Object.keys(existingAttributes);

  console.log(`   ✓ Schema retrieved successfully`);
  console.log(`   → Existing custom attributes: ${existingAttributeNames.length}`);

  if (existingAttributeNames.length > 0) {
    console.log('   → Current attributes:');
    existingAttributeNames.forEach(attr => console.log(`     • ${attr}`));
  }
  console.log('');

  // Determine which attributes need to be created
  const attributesToCreate = columns.filter(col => !existingAttributeNames.includes(col));
  const attributesAlreadyExist = columns.filter(col => existingAttributeNames.includes(col));

  if (attributesAlreadyExist.length > 0) {
    console.log(`   ✓ ${attributesAlreadyExist.length} attribute(s) already exist (skipping):`);
    attributesAlreadyExist.forEach(attr => console.log(`     • ${attr}`));
    console.log('');
  }

  if (attributesToCreate.length === 0) {
    console.log('   ✓ All required attributes already exist');
    console.log('   → No new attributes need to be created');
    return columns; // Return all columns for mapping
  }

  console.log(`   → Creating ${attributesToCreate.length} new custom attribute(s)...`);
  console.log('');

  let successCount = 0;
  let failureCount = 0;
  const successfullyCreated = [];

  for (const attributeName of attributesToCreate) {
    try {
      console.log(`   → Creating attribute: "${attributeName}"`);
      console.log(`     API Call: POST /api/v1/meta/schemas/apps/${appId}/default`);
      await createCustomAttribute(config, appId, attributeName);
      console.log(`     ✓ Successfully created`);
      successCount++;
      successfullyCreated.push(attributeName);
    } catch (error) {
      console.error(`     ✗ Failed: ${error.message}`);
      failureCount++;
    }
    console.log('');
  }

  console.log('   📊 Custom Attribute Summary:');
  console.log(`     • Total columns in CSV: ${allColumns.total}`);
  console.log(`     • Already existed: ${attributesAlreadyExist.length}`);
  console.log(`     • Successfully created: ${successCount}`);
  if (failureCount > 0) {
    console.log(`     • Failed to create: ${failureCount}`);
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

          // Build app user profile
          const appUserProfile = {};
          for (const [key, value] of Object.entries(record)) {
            if (value) appUserProfile[key] = value;
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
    console.log('   ' + '─'.repeat(50));
    console.log(`   📊 SYNC RESULTS [${syncTime}]`);
    console.log('   ' + '─'.repeat(50));
    console.log(`     Entitlements Created: ${entitlementsCreated}`);
    console.log(`     Users Added:          ${added}`);
    console.log(`     Users Updated:        ${updated}`);
    console.log(`     Users Removed:        ${removed}`);
    if (failed > 0) {
      console.log(`     Failed:               ${failed}`);
    }
    console.log(`     Total in Okta:        ${oktaAppUsers.length}`);
    console.log(`     Total in CSV:         ${Object.keys(csvUsers).length}`);
    console.log('   ' + '─'.repeat(50));
    console.log('');

    return { added, updated, removed, failed, entitlementsCreated };
  } catch (error) {
    console.log(`   ✗ Sync error: ${error.message}`);
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
  console.log('='.repeat(70));
  console.log('🔁 SYNC MODE ENABLED');
  console.log('='.repeat(70));
  console.log(`   Checking for changes every ${intervalMinutes} minute(s)`);
  console.log('   Press Ctrl+C to stop');
  console.log('');

  // Run initial sync
  await syncUsers(config, app.id, csvFilePath, resourceId, entitlementsMap);

  // Schedule periodic syncs
  const syncLoop = async () => {
    const now = new Date().toLocaleTimeString();
    console.log(`⏰ [${now}] Running scheduled sync...`);
    console.log('');
    await syncUsers(config, app.id, csvFilePath, resourceId, entitlementsMap);
    console.log(`   Next sync in ${intervalMinutes} minute(s)`);
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
\x1b[36m    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║\x1b[0m\x1b[33m       ██╗██████╗ ███████╗███╗   ██╗████████╗██╗████████╗██╗   ██╗\x1b[36m  ║
    ║\x1b[0m\x1b[33m       ██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║╚══██╔══╝╚██╗ ██╔╝\x1b[36m  ║
    ║\x1b[0m\x1b[33m       ██║██║  ██║█████╗  ██╔██╗ ██║   ██║   ██║   ██║    ╚████╔╝\x1b[36m   ║
    ║\x1b[0m\x1b[33m       ██║██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██║   ██║     ╚██╔╝\x1b[36m    ║
    ║\x1b[0m\x1b[33m       ██║██████╔╝███████╗██║ ╚████║   ██║   ██║   ██║      ██║\x1b[36m     ║
    ║\x1b[0m\x1b[33m       ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝   ╚═╝      ╚═╝\x1b[36m     ║
    ║                                                               ║
    ║\x1b[0m\x1b[35m           ┌─────────────────────────────────────────┐\x1b[36m           ║
    ║\x1b[0m\x1b[35m           │\x1b[0m  🔐 Okta Disconnected App Governance    \x1b[35m│\x1b[36m           ║
    ║\x1b[0m\x1b[35m           │\x1b[0m     Connector for Identity Sync         \x1b[35m│\x1b[36m           ║
    ║\x1b[0m\x1b[35m           └─────────────────────────────────────────┘\x1b[36m           ║
    ║                                                               ║
    ║\x1b[0m     CSV → Users → Entitlements → Governance → Compliance\x1b[36m        ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝\x1b[0m
`;
  console.log(banner);
}

async function main() {
  try {
    printBanner();
    console.log('');

    // Get configuration (from file or prompt user)
    console.log('📋 STEP 1: Loading Configuration');
    console.log('   → Checking for existing configuration file (config.json)...');
    let config = await getConfig();
    console.log('   ✓ Configuration loaded successfully');
    console.log(`   ✓ Connected to Okta tenant: ${config.oktaDomain}`);
    console.log('');

    // Find CSV files in current directory
    console.log('📂 STEP 2: CSV File Discovery');
    console.log('   → Scanning current directory for .csv files...');
    const csvFiles = findCsvFiles();

    if (csvFiles.length === 0) {
      console.log('   ✗ No CSV files found in the current directory.');
      console.log('');
      console.log('💡 TIP: Place a CSV file in the current directory and run again.');
      console.log('   The CSV filename will be used as the application name in Okta.');
      process.exit(0);
    }

    // Determine which CSV file to process
    let selectedCsvFile;

    if (csvFiles.length === 1) {
      // Only one CSV file, use it automatically
      selectedCsvFile = csvFiles[0];
      console.log(`   ✓ Found 1 CSV file: ${selectedCsvFile}`);
      console.log('   → Automatically selected for processing');
    } else {
      // Multiple CSV files found
      console.log(`   ✓ Found ${csvFiles.length} CSV files:`);
      csvFiles.forEach(file => console.log(`     • ${file}`));
      console.log('');

      // Check if there's a saved selection
      if (config.selectedCsvFile && csvFiles.includes(config.selectedCsvFile)) {
        selectedCsvFile = config.selectedCsvFile;
        console.log('   → Using previously selected file from configuration');
        console.log(`   ✓ Selected: ${selectedCsvFile}`);
        console.log('');
        console.log('   💡 TIP: To change selection, delete config.json and run again');
      } else {
        console.log('   → No saved selection found, prompting for user input...');
        selectedCsvFile = await selectCsvFile(csvFiles);

        // Save selection to config
        config.selectedCsvFile = selectedCsvFile;
        await saveConfig(config);
        console.log('   ✓ Selection saved to configuration file');
      }
    }
    console.log('');

    // Process the selected CSV file
    const appName = path.basename(selectedCsvFile, '.csv');
    console.log('🔧 STEP 3: Application Processing');
    console.log(`   → CSV File: ${selectedCsvFile}`);
    console.log(`   → Application Name: "${appName}"`);
    console.log('');

    // Check if app exists
    console.log('   → Querying Okta API to check if application exists...');
    console.log(`   → API Call: GET /api/v1/apps?q=${encodeURIComponent(appName)}`);
    const existingApp = await findAppByName(config, appName);

    let app;
    if (existingApp) {
      console.log('   ✓ Application found in Okta!');
      console.log('');
      console.log('   📊 Application Details:');
      console.log(`     • App ID: ${existingApp.id}`);
      console.log(`     • Status: ${existingApp.status}`);
      console.log(`     • Sign-On Mode: ${existingApp.signOnMode}`);
      console.log('');
      console.log('   → Skipping application creation (already exists)');
      app = existingApp;
    } else {
      console.log('   ℹ Application does not exist in Okta');
      console.log('   → Preparing SAML 2.0 application definition...');
      console.log('   → API Call: POST /api/v1/apps');
      console.log('');
      const newApp = await createSamlApp(config, appName);
      console.log('   ✓ Application created successfully!');
      console.log('');
      console.log('   📊 New Application Details:');
      console.log(`     • App ID: ${newApp.id}`);
      console.log(`     • Name: ${newApp.label}`);
      console.log(`     • Status: ${newApp.status}`);
      console.log(`     • Sign-On Mode: ${newApp.signOnMode}`);
      console.log('');
      console.log('   💡 NOTE: SAML settings use placeholder values.');
      console.log('   Update SSO URLs and audience in Okta Admin Console.');
      app = newApp;
    }
    console.log('');

    // Register app with governance and enable entitlement management
    console.log('🔐 STEP 4: Entitlement Management Configuration');
    let governanceResourceId = null;

    // First check if resource already exists
    console.log('   → Checking if app is registered in Governance...');
    console.log(`   → API Call: GET /governance/api/v1/resources?filter=source.id eq "${app.id}"`);
    governanceResourceId = await getGovernanceResourceId(config, app.id);

    if (!governanceResourceId) {
      // Try to opt-in the app to governance / enable entitlement management
      console.log('   → App not registered in Governance, enabling entitlement management...');
      try {
        const resource = await registerGovernanceResource(config, app.id, app.label);
        governanceResourceId = resource.id;
        console.log(`   ✓ Governance resource ID: ${governanceResourceId}`);
      } catch (error) {
        console.log(`   ⚠ Could not enable entitlement management: ${error.message}`);
        console.log('   → This feature requires Okta Identity Governance (OIG) license');
        console.log('   → Entitlements may need to be enabled manually in Admin Console');
        console.log('');
      }
    } else {
      console.log(`   ✓ App already registered in Governance: ${governanceResourceId}`);
    }

    // Enable entitlement management if we have a resource ID
    if (governanceResourceId) {
      console.log('   → Enabling entitlement management...');
      console.log(`   → API Call: PUT /governance/api/v1/resources/${governanceResourceId}/entitlement-management`);
      try {
        await enableEntitlementManagement(config, governanceResourceId);
        console.log('   ✓ Entitlement management enabled successfully');
        console.log('   → App is now ready for entitlement creation');
      } catch (error) {
        console.log(`   ⚠ Could not enable entitlement management: ${error.message}`);
        console.log('   → Entitlement management may already be enabled');
      }
    }
    console.log('');

    // Process custom attributes from CSV columns
    console.log('🏷️  STEP 5: Custom Attribute Management');
    console.log('   → Reading CSV column headers...');
    console.log('   → Filtering out enterprise columns (starting with "ent_")...');
    const attributes = await processCustomAttributes(config, app.id, selectedCsvFile);

    // Process attribute mappings to Okta user profile
    if (attributes && attributes.length > 0) {
      await processAttributeMappings(config, app.id, attributes);
    }

    // Process entitlements from CSV
    const entitlementsMap = await processEntitlements(config, app.id, selectedCsvFile, governanceResourceId);

    // Process users from CSV - create/update and assign to app with entitlements
    await processUsers(config, app.id, selectedCsvFile, governanceResourceId, entitlementsMap);

    console.log('');
    console.log('='.repeat(70));
    console.log('✅ Initial Processing Complete!');
    console.log('='.repeat(70));
    console.log('');

    // Check if sync mode is enabled
    if (config.syncInterval && config.syncInterval > 0) {
      // Enter sync mode - will run indefinitely
      await runSyncMode(config, app, selectedCsvFile, governanceResourceId, entitlementsMap);
    } else {
      // One-time run - show next steps and exit
      console.log('📍 Next Steps:');
      console.log('   1. Login to Okta Admin Console');
      console.log(`   2. Navigate to Applications → ${appName}`);
      console.log('   3. Review users assigned to the app under Assignments tab');
      console.log('   4. Check entitlements under Identity Governance → Resources');
      console.log('');
      console.log('💡 TIP: To enable automatic sync mode, add "syncInterval": 5 to config.json');
      console.log('   This will check for CSV changes every 5 minutes.');
      console.log('');
    }

  } catch (error) {
    console.log('');
    console.error('❌ ERROR:', error.message);
    console.log('');
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
