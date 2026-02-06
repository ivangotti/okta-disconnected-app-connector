import okta from '@okta/okta-sdk-nodejs';
const { Client } = okta;
import { getConfig, saveConfig, selectCsvFile, getAccessToken } from './config.js';
import fs from 'fs';
import path from 'path';
import { parse } from 'csv-parse/sync';

// Global access token cache
let cachedAccessToken = null;

/**
 * Get authorization header for API calls
 * Uses OAuth Bearer token if available, falls back to SSWS
 */
async function getAuthHeader(config) {
  if (config.clientId && config.clientSecret) {
    // Use OAuth - get or reuse cached token
    if (!cachedAccessToken) {
      cachedAccessToken = await getAccessToken(config);
    }
    return `Bearer ${cachedAccessToken}`;
  } else if (config.apiToken) {
    // Fallback to SSWS token
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

    // Filter out columns starting with "ent_"
    return columns.filter(col => !col.startsWith('ent_'));
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

    // Separate included and excluded columns
    const included = allColumns.filter(col => !col.startsWith('ent_'));
    const excluded = allColumns.filter(col => col.startsWith('ent_'));

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
async function registerGovernanceResource(config, appId) {
  try {
    // First try to register the app as a resource
    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/resources`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          source: {
            id: appId
          }
        })
      }
    );

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`Error registering governance resource: ${error.message}`);
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
    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/resources/${resourceId}/entitlements`,
      {
        method: 'POST',
        headers: {
          'Authorization': await getAuthHeader(config),
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
async function getAppEntitlements(config, resourceId) {
  try {
    const response = await fetch(
      `https://${config.oktaDomain}/governance/api/v1/resources/${resourceId}/entitlements`,
      {
        headers: {
          'Authorization': await getAuthHeader(config),
          'Accept': 'application/json'
        }
      }
    );

    if (response.status === 404 || response.status === 405) {
      return null;
    }

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorBody}`);
    }

    return await response.json();
  } catch (error) {
    // If governance API is not available, return null
    if (error.message.includes('404') || error.message.includes('405') || error.message.includes('not found')) {
      return null;
    }
    throw new Error(`Error fetching entitlements: ${error.message}`);
  }
}

/**
 * Process entitlement catalog and create entitlements in Okta
 */
async function processEntitlements(config, appId, csvFilePath) {
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

  // Get governance resource ID for the app
  console.log('   → Fetching governance resource ID for app...');
  console.log(`   → API Call: GET /governance/api/v1/resources?filter=source.id eq "${appId}"`);

  const resourceId = await getGovernanceResourceId(config, appId);

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

  const existingEntitlements = await getAppEntitlements(config, resourceId);

  if (existingEntitlements === null) {
    console.log('   ⚠ Could not fetch entitlements from governance API');
    console.log('');
    return;
  }

  console.log(`   ✓ Found ${existingEntitlements.length} existing entitlements`);
  console.log('');

  // Create entitlements from catalog
  console.log('   → Creating entitlements from CSV catalog...');
  console.log('');

  let created = 0;
  let skipped = 0;
  let failed = 0;

  for (const [column, values] of Object.entries(catalog)) {
    const attributeName = column.substring(4); // Remove 'ent_' prefix
    console.log(`   → Processing ${attributeName} entitlements:`);

    for (const value of values) {
      try {
        // Check if entitlement already exists
        const exists = existingEntitlements.some(ent =>
          ent.name && ent.name.toLowerCase() === value.toLowerCase()
        );

        if (exists) {
          console.log(`     • ${value} (already exists)`);
          skipped++;
          continue;
        }

        // Create entitlement
        const entitlementData = {
          name: value,
          attribute: attributeName,
          value: JSON.stringify({ name: value })
        };

        await createEntitlement(config, resourceId, entitlementData);
        console.log(`     ✓ ${value} (created)`);
        created++;
      } catch (error) {
        console.log(`     ✗ ${value} (failed: ${error.message})`);
        failed++;
      }
    }
    console.log('');
  }

  console.log('   📊 Entitlement Creation Summary:');
  console.log(`     • Total unique entitlements: ${totalEntitlements}`);
  console.log(`     • Successfully created: ${created}`);
  console.log(`     • Already existed: ${skipped}`);
  if (failed > 0) {
    console.log(`     • Failed: ${failed}`);
  }
  console.log('');
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
  console.log(`     • Excluded (ent_*): ${excludedColumns.length}`);
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
      // Try to register the app as a governance resource
      console.log('   → App not registered in Governance, registering now...');
      console.log(`   → API Call: POST /governance/api/v1/resources`);
      try {
        const resource = await registerGovernanceResource(config, app.id);
        governanceResourceId = resource.id;
        console.log(`   ✓ App registered as governance resource: ${governanceResourceId}`);
      } catch (error) {
        console.log(`   ⚠ Could not register governance resource: ${error.message}`);
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
    await processEntitlements(config, app.id, selectedCsvFile);

    console.log('');
    console.log('='.repeat(70));
    console.log('✅ Processing Complete!');
    console.log('='.repeat(70));
    console.log('');
    console.log('📍 Next Steps:');
    console.log('   1. Login to Okta Admin Console');
    console.log(`   2. Navigate to Applications → ${appName}`);
    console.log('   3. Configure SAML settings (SSO URLs, Audience, etc.)');
    console.log('   4. Review custom attributes under Provisioning → To App');
    console.log('   5. Verify profile mappings under Provisioning → To Okta');
    console.log('   6. Check entitlements under Identity Governance → Resources (if available)');
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
