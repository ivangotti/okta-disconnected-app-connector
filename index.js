import okta from '@okta/okta-sdk-nodejs';
const { Client } = okta;
import { getConfig, saveConfig, selectCsvFile, getAccessToken, getAccessTokenDeviceFlow } from './config.js';
import fs from 'fs';
import path from 'path';
import { parse } from 'csv-parse/sync';

// Global access token cache
let cachedAccessToken = null;

/**
 * Get authorization header for API calls
 * Supports Device Flow, Client Credentials, and SSWS token
 */
async function getAuthHeader(config) {
  if (config.clientId) {
    // Use OAuth - get or reuse cached token
    if (!cachedAccessToken) {
      if (config.authFlow === 'device') {
        // Device flow - user authenticates in browser
        cachedAccessToken = await getAccessTokenDeviceFlow(config);
      } else if (config.clientSecret || config.privateKey || config.privateKeyPath) {
        // Client credentials flow (with client_secret or private_key_jwt)
        cachedAccessToken = await getAccessToken(config);
      } else {
        throw new Error('OAuth configuration incomplete: missing authentication credentials (clientSecret, privateKey, or privateKeyPath)');
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
      console.log(`     ✗ ${attributeName} failed: ${error.message}`);
      failed++;
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
 * Assign a single entitlement grant to a user
 * Uses the Grants API which is the proper way to assign entitlements
 */
async function createEntitlementGrant(config, resourceId, userId, entitlementId, entitlementValueId = null) {
  try {
    // Use SSWS token for governance endpoints if available
    const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

    const grantData = {
      grantType: "ENTITLEMENT",
      principalId: userId,
      resourceId: resourceId,
      entitlementId: entitlementId,
      target: {
        externalId: userId
      }
    };

    // Add entitlement value ID for multiValue entitlements
    if (entitlementValueId) {
      grantData.entitlementValueId = entitlementValueId;
    }

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
    let failed = 0;

    for (let i = 0; i < records.length; i++) {
      const record = records[i];
      const username = record.Username || record.username || record.email;

      if (!username) {
        console.log(`   ⚠ Skipping row - no username/email found`);
        failed++;
        continue;
      }

      // Declare variables outside try block so they're accessible in catch for retry
      let userId;
      let appUserProfile;

      try {
        console.log(`   → Processing user ${i + 1}/${records.length}: ${username}`);

        // Build user profile
        const userProfile = {
          login: username,
          email: record.email || username,
          firstName: record.firstName || '',
          lastName: record.lastName || ''
        };

        // Add optional fields if present
        if (record.employeeId) userProfile.employeeNumber = record.employeeId;
        if (record.department) userProfile.department = record.department;

        // Check if user exists
        const existingUser = await findUser(config, username);
        if (existingUser) {
          console.log(`     → User exists (${existingUser.id}), updating...`);
          await updateUser(config, existingUser.id, { profile: userProfile });
          userId = existingUser.id;
          updated++;
        } else {
          console.log(`     → User does not exist, creating...`);
          const newUser = await createUser(config, {
            profile: userProfile,
            credentials: {
              password: { value: 'TempPass123!' } // Temporary password
            }
          });
          userId = newUser.id;
          created++;
          console.log(`     ✓ User created (${userId})`);
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
        console.log(`     → Assigning user to app with entitlements...`);
        await assignUserToApp(config, appId, userId, appUserProfile);
        console.log(`     ✓ User assigned to app with attributes and entitlements`);
        assigned++;

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
    console.log(`     • Assigned to app with entitlements: ${assigned}`);
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

async function main() {
  try {
    console.log('='.repeat(70));
    console.log('  CSV Agent - Okta SAML Application Automation');
    console.log('='.repeat(70));
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
    console.log('✅ Processing Complete!');
    console.log('='.repeat(70));
    console.log('');
    console.log('📍 Next Steps:');
    console.log('   1. Login to Okta Admin Console');
    console.log(`   2. Navigate to Applications → ${appName}`);
    console.log('   3. Configure SAML settings (SSO URLs, Audience, etc.)');
    console.log('   4. Review users assigned to the app under Assignments tab');
    console.log('   5. Review custom attributes under Provisioning → To App');
    console.log('   6. Verify profile mappings under Provisioning → To Okta');
    console.log('   7. Check entitlements under Identity Governance → Resources');
    console.log('   8. Verify user entitlement assignments if governance is enabled');
    console.log('');

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
