import { getConfig, getAccessToken, getAccessTokenDeviceFlow } from './config.js';
import fs from 'fs';
import { parse } from 'csv-parse/sync';

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  // Text colors
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  // Background colors
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
  bgMagenta: '\x1b[45m',
};

// Helper functions for colored output
const c = {
  success: (text) => `${colors.green}${text}${colors.reset}`,
  warning: (text) => `${colors.yellow}${text}${colors.reset}`,
  error: (text) => `${colors.red}${text}${colors.reset}`,
  info: (text) => `${colors.cyan}${text}${colors.reset}`,
  data: (text) => `${colors.white}${colors.bold}${text}${colors.reset}`,
  dim: (text) => `${colors.dim}${text}${colors.reset}`,
  highlight: (text) => `${colors.magenta}${text}${colors.reset}`,
  label: (text) => `${colors.blue}${text}${colors.reset}`,
};

// Global access token cache (shared with index.js pattern)
let cachedAccessToken = null;
let tokenExpiresAt = null;

/**
 * Check if the cached token is expired or about to expire
 */
function isTokenExpired() {
  if (!tokenExpiresAt) return true;
  const bufferMs = 5 * 60 * 1000; // 5 minutes
  return Date.now() >= (tokenExpiresAt - bufferMs);
}

/**
 * Get authorization header for API calls
 */
async function getAuthHeader(config, forceRefresh = false) {
  if (config.clientId) {
    if (!cachedAccessToken || isTokenExpired() || forceRefresh) {
      if (config.authFlow === 'device') {
        cachedAccessToken = await getAccessTokenDeviceFlow(config);
        tokenExpiresAt = Date.now() + (60 * 60 * 1000);
      } else if (config.clientSecret || config.privateKey || config.privateKeyPath) {
        cachedAccessToken = await getAccessToken(config);
        tokenExpiresAt = Date.now() + (60 * 60 * 1000);
      } else {
        throw new Error('OAuth configuration incomplete: missing authentication credentials');
      }
    }
    return `Bearer ${cachedAccessToken}`;
  } else if (config.apiToken) {
    return `SSWS ${config.apiToken}`;
  } else {
    throw new Error('No authentication credentials found in configuration');
  }
}

/**
 * Extract permission bundle from a record
 * Converts ent_* columns into a PermissionBundle object
 *
 * @param {Object} record - User record with ent_* columns
 * @returns {Object} - Bundle object like {ent_Role: ["Manager"], ent_Dept: ["Finance"]}
 */
function extractBundle(record) {
  const bundle = {};

  for (const [key, value] of Object.entries(record)) {
    // Only process entitlement columns (ent_*)
    if (key.startsWith('ent_') && value) {
      // Split comma-separated values and trim whitespace
      const values = value.toString().split(',').map(v => v.trim()).filter(v => v);
      if (values.length > 0) {
        bundle[key] = values.sort(); // Sort for consistency
      }
    }
  }

  return bundle;
}

/**
 * Create a deterministic signature from a permission bundle
 * Uses sorted JSON stringification for consistency
 *
 * @param {Object} bundle - Permission bundle object
 * @returns {string} - Unique signature string
 */
function createBundleSignature(bundle) {
  // Sort keys and values for deterministic output
  const sortedBundle = {};
  const keys = Object.keys(bundle).sort();

  for (const key of keys) {
    sortedBundle[key] = Array.isArray(bundle[key]) ? bundle[key].sort() : bundle[key];
  }

  return JSON.stringify(sortedBundle);
}

/**
 * Generate a meaningful role name from a permission bundle
 * Creates names like "FinancialManager" or "Role_1"
 *
 * @param {Object} bundle - Permission bundle
 * @param {number} index - Role index for fallback naming
 * @returns {string} - Generated role name
 */
function generateRoleName(bundle, index) {
  const parts = [];

  // Try to extract meaningful name components
  for (const [entName, values] of Object.entries(bundle)) {
    // Get entitlement name without ent_ prefix
    const cleanEntName = entName.replace(/^ent_/, '');

    // Take first value if multiple
    const value = Array.isArray(values) ? values[0] : values;

    // Clean up value (remove spaces, special chars)
    const cleanValue = value.replace(/[^a-zA-Z0-9]/g, '');

    parts.push(cleanValue);
  }

  // Create camelCase name or fallback to Role_N
  if (parts.length > 0) {
    const name = parts.join('_');
    return name.length > 50 ? `Role_${index + 1}` : name;
  }

  return `Role_${index + 1}`;
}

/**
 * Generate a human-readable description for a role
 * Creates descriptions like "8 users (19.0%) - Manager, Senior roles in Finance department"
 *
 * @param {Object} bundle - Permission bundle
 * @param {number} userCount - Number of users with this role
 * @param {number} totalUsers - Total number of users
 * @returns {string} - Generated description
 */
function generateRoleDescription(bundle, userCount, totalUsers) {
  const percentage = totalUsers > 0 ? ((userCount / totalUsers) * 100).toFixed(1) : '0.0';
  const parts = [];

  for (const [entName, values] of Object.entries(bundle)) {
    const cleanEntName = entName.replace(/^ent_/, '');
    const valueList = Array.isArray(values) ? values.join(', ') : values;
    parts.push(`${valueList} (${cleanEntName})`);
  }

  const entitlementDesc = parts.join(' + ');
  return `${userCount} users (${percentage}%) - ${entitlementDesc}`;
}

/**
 * Core role mining algorithm using exact match clustering
 * Groups users with identical permission bundles
 *
 * @param {Array} records - Array of user records with ent_* columns
 * @param {number} minUserThreshold - Minimum users required for a role
 * @returns {Object} - Analysis results with role candidates
 */
function analyzeRoles(records, minUserThreshold = 2) {
  const bundleMap = new Map(); // signature → users[]

  console.log(`   ${c.info('🔍')} Analyzing role patterns...`);

  // Extract bundles and group by signature
  for (const record of records) {
    const bundle = extractBundle(record);

    // Skip records with no entitlements
    if (Object.keys(bundle).length === 0) continue;

    const signature = createBundleSignature(bundle);

    if (!bundleMap.has(signature)) {
      bundleMap.set(signature, []);
    }

    // Get username from record (handle different column name variations)
    const username = record.username || record.Username || record.email || record.Email || 'unknown';

    bundleMap.get(signature).push({
      username: username,
      bundle: bundle
    });
  }

  console.log(`   ${c.success('✓')} Found ${c.data(bundleMap.size)} unique permission combinations`);

  // Debug: Show top 3 most common patterns
  const sortedBySize = Array.from(bundleMap.entries()).sort((a, b) => b[1].length - a[1].length);
  if (sortedBySize.length > 0) {
    console.log(`   ${c.dim('→')} Top pattern has ${c.highlight(sortedBySize[0][1].length)} users`);
  }

  // Create role candidates meeting threshold
  const roleCandidates = [];
  let roleIndex = 0;

  for (const [signature, users] of bundleMap.entries()) {
    if (users.length >= minUserThreshold) {
      const bundle = users[0].bundle;

      roleCandidates.push({
        roleName: generateRoleName(bundle, roleIndex++),
        userCount: users.length,
        percentage: (users.length / records.length) * 100,
        users: users.map(u => u.username),
        permissions: bundle,
        description: generateRoleDescription(bundle, users.length, records.length)
      });
    }
  }

  // Sort by impact (user count descending)
  roleCandidates.sort((a, b) => b.userCount - a.userCount);

  const usersInRoles = roleCandidates.reduce((sum, r) => sum + r.userCount, 0);

  console.log(`   ${c.success('✓')} Discovered ${c.data(roleCandidates.length)} role candidates ${c.dim(`(threshold: ${minUserThreshold} users)`)}`);

  return {
    totalUsers: records.length,
    uniqueProfiles: bundleMap.size,
    roleCandidates: roleCandidates,
    coverage: {
      usersInRoles: usersInRoles,
      percentage: records.length > 0 ? (usersInRoles / records.length) * 100 : 0
    }
  };
}

/**
 * Read CSV file and build user-entitlement matrix
 * Reads directly from CSV to avoid Okta API query issues
 *
 * @param {string} csvFilePath - Path to CSV file
 * @returns {Array} - Array of records with username and ent_* columns
 */
async function readCsvAndBuildMatrix(csvFilePath) {
  console.log(`   ${c.info('📄')} Reading user entitlement data from CSV...`);
  console.log(`   ${c.dim('   File:')} ${c.data(csvFilePath)}`);

  try {
    // Read and parse CSV file
    const fileContent = fs.readFileSync(csvFilePath, 'utf8');
    const records = parse(fileContent, {
      columns: true,
      skip_empty_lines: true,
      trim: true
    });

    console.log(`   ${c.success('✓')} Loaded ${c.data(records.length)} user records from CSV`);

    // Count users with entitlements (ent_* columns)
    const usersWithEntitlements = records.filter(record => {
      return Object.keys(record).some(key => key.startsWith('ent_') && record[key]);
    });

    console.log(`   ${c.success('✓')} Found ${c.data(usersWithEntitlements.length)} users with entitlements`);

    if (usersWithEntitlements.length === 0) {
      console.log(`   ${c.warning('ℹ')} No users with entitlements found - skipping role mining`);
    }

    return usersWithEntitlements;

  } catch (error) {
    throw new Error(`Failed to read CSV: ${error.message}`);
  }
}

/**
 * Convert a role candidate to Okta bundle payload
 * Maps permission bundle to entitlement IDs and value IDs
 *
 * @param {Object} candidate - Role candidate from analysis
 * @param {Map} entitlementsMap - Map of entitlement names to IDs and values
 * @param {string} appId - Application ID for the target
 * @returns {Object} - Bundle payload for Okta API
 */
function convertCandidateToBundle(candidate, entitlementsMap, appId) {
  const entitlements = [];

  // Convert each permission in the bundle to entitlement format
  for (const [entName, values] of Object.entries(candidate.permissions)) {
    const cleanEntName = entName.replace(/^ent_/, '');
    // Handle both Map and Object, case-insensitive lookup
    let entitlementData;
    if (entitlementsMap instanceof Map) {
      entitlementData = entitlementsMap.get(cleanEntName) || entitlementsMap.get(cleanEntName.toLowerCase());
    } else {
      entitlementData = entitlementsMap[cleanEntName] || entitlementsMap[cleanEntName.toLowerCase()];
    }

    if (!entitlementData) {
      console.log(`   ${c.warning('⚠')} Entitlement ${c.data(`"${cleanEntName}"`)} not found in entitlementsMap, skipping`);
      continue;
    }

    // Map value names to value IDs
    const valueIds = [];
    const valueArray = Array.isArray(values) ? values : [values];

    for (const valueName of valueArray) {
      const valueData = entitlementData.values?.find(v => v.name === valueName);
      if (valueData) {
        valueIds.push({ id: valueData.id });
      } else {
        console.log(`   ${c.warning('⚠')} Value ${c.data(`"${valueName}"`)} not found for entitlement ${c.data(`"${cleanEntName}"`)}, skipping`);
      }
    }

    if (valueIds.length > 0) {
      entitlements.push({
        id: entitlementData.id,
        values: valueIds
      });
    }
  }

  // Return bundle payload with target application
  return {
    name: candidate.roleName,
    description: candidate.description,
    target: {
      externalId: appId,
      type: "APPLICATION"
    },
    entitlements: entitlements
  };
}

/**
 * Create a bundle in Okta Governance via API
 *
 * @param {Object} config - Okta configuration
 * @param {Object} payload - Bundle payload
 * @returns {Object} - Created bundle response
 */
async function createBundle(config, payload) {
  // Prefer SSWS for governance API calls (same as optIn endpoint)
  const authHeader = config.apiToken ? `SSWS ${config.apiToken}` : await getAuthHeader(config);

  const response = await fetch(
    `https://${config.oktaDomain}/governance/api/v1/entitlement-bundles`,
    {
      method: 'POST',
      headers: {
        'Authorization': authHeader,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    }
  );

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`HTTP ${response.status}: ${errorBody}`);
  }

  return await response.json();
}

/**
 * Create Okta bundles from role candidates
 *
 * @param {Object} config - Okta configuration
 * @param {string} appId - Application ID (target for bundles)
 * @param {string} resourceId - Governance resource ID
 * @param {Array} candidates - Array of role candidates
 * @param {Map} entitlementsMap - Map of entitlement names to IDs and values
 * @returns {Array} - Array of created bundles
 */
async function createBundlesFromCandidates(config, appId, resourceId, candidates, entitlementsMap) {
  console.log('');
  console.log(`   ${c.info('🏗️')}  Creating Bundles in Okta Governance`);
  console.log(`   ${c.dim('─'.repeat(50))}`);
  console.log(`   ${c.label('Target App ID:')} ${c.data(appId)}`);
  console.log('');

  const createdBundles = [];

  for (const candidate of candidates) {
    try {
      const payload = convertCandidateToBundle(candidate, entitlementsMap, appId);

      // Skip if no valid entitlements
      if (payload.entitlements.length === 0) {
        console.log(`   ${c.warning('⚠')} Skipping ${c.data(candidate.roleName)} - no valid entitlements`);
        continue;
      }

      const bundle = await createBundle(config, payload);
      createdBundles.push(bundle);

      console.log(`   ${c.success('✓')} Created: ${c.highlight(candidate.roleName)}`);

    } catch (error) {
      console.log(`   ${c.error('✗')} Failed: ${c.data(candidate.roleName)} - ${c.dim(error.message)}`);
      // Continue with next bundle
    }
  }

  return createdBundles;
}

/**
 * Main entry point for role mining
 * Analyzes CSV data to find role patterns and creates bundles
 *
 * @param {Object} config - Okta configuration
 * @param {string} appId - Application ID
 * @param {string} resourceId - Governance resource ID
 * @param {Map} entitlementsMap - Map of entitlement names to IDs and values
 * @param {string} csvFilePath - Path to CSV file with user entitlement data
 * @returns {Object} - Summary statistics
 */
export async function runRoleMining(config, appId, resourceId, entitlementsMap, csvFilePath) {
  console.log('');
  console.log(c.info('═'.repeat(70)));
  console.log(`${c.info('🎯')} ${c.data('STEP 9: Role Mining & Bundle Creation')}`);
  console.log(c.info('═'.repeat(70)));

  // Show available entitlements
  if (entitlementsMap) {
    const keys = entitlementsMap instanceof Map
      ? Array.from(entitlementsMap.keys())
      : Object.keys(entitlementsMap);
    console.log(`   ${c.label('Available Entitlements:')} ${c.dim(keys.join(', '))}`);
  }

  try {
    // Get role mining configuration with defaults
    const roleMiningConfig = config.roleMining || {};
    const minUserThreshold = roleMiningConfig.minUserThreshold || 2;
    const createBundlesEnabled = roleMiningConfig.createBundles !== false;

    // Step 1: Read CSV and build user-entitlement matrix
    const records = await readCsvAndBuildMatrix(csvFilePath);

    if (records.length === 0) {
      console.log('');
      console.log(`   ${c.warning('ℹ')} No user grants found - skipping role mining`);
      return {
        bundlesCreated: 0,
        usersCovered: 0,
        coveragePercentage: 0
      };
    }

    console.log(`   ${c.success('✓')} Built user-entitlement matrix: ${c.data(records.length)} users`);

    // Debug: Show sample records
    if (records.length > 0) {
      console.log('');
      console.log(`   ${c.info('👤')} ${c.label('Sample User Record:')}`);
      const sampleUser = records[0];
      const entColumns = Object.keys(sampleUser).filter(k => k.startsWith('ent_'));
      console.log(`   ${c.dim('   Username:')} ${c.data(sampleUser.username || sampleUser.Username || 'unknown')}`);
      for (const col of entColumns) {
        const cleanCol = col.replace('ent_', '');
        console.log(`   ${c.dim(`   ${cleanCol}:`)} ${c.highlight(sampleUser[col])}`);
      }
    }

    // Step 2: Analyze roles
    const analysis = analyzeRoles(records, minUserThreshold);

    // Display role candidates
    if (analysis.roleCandidates.length === 0) {
      console.log('');
      console.log(`   ${c.warning('ℹ')} No roles met the threshold of ${c.data(minUserThreshold)} users`);
      return {
        bundlesCreated: 0,
        usersCovered: 0,
        coveragePercentage: 0
      };
    }

    console.log('');
    console.log(`   ${c.info('📊')} ${c.label('Discovered Role Candidates:')}`);
    console.log(`   ${c.dim('─'.repeat(50))}`);
    for (let i = 0; i < Math.min(analysis.roleCandidates.length, 10); i++) {
      const candidate = analysis.roleCandidates[i];
      const pct = candidate.percentage.toFixed(1);
      console.log(`   ${c.data(`${i + 1}.`)} ${c.highlight(candidate.roleName)}`);
      console.log(`      ${c.label('Users:')} ${c.data(candidate.userCount)} ${c.dim(`(${pct}% coverage)`)}`);

      // Show entitlements
      const entParts = [];
      for (const [entName, values] of Object.entries(candidate.permissions)) {
        const cleanName = entName.replace(/^ent_/, '');
        const valueList = Array.isArray(values) ? values.join(', ') : values;
        entParts.push(`${c.label(cleanName)}=${c.data(`[${valueList}]`)}`);
      }
      console.log(`      ${c.label('Entitlements:')} ${entParts.join(', ')}`);
      console.log('');
    }

    if (analysis.roleCandidates.length > 10) {
      console.log(`   ${c.dim(`... and ${analysis.roleCandidates.length - 10} more`)}`);
    }

    // Step 3: Create bundles (if enabled)
    let createdBundles = [];

    if (createBundlesEnabled) {
      createdBundles = await createBundlesFromCandidates(
        config,
        appId,
        resourceId,
        analysis.roleCandidates,
        entitlementsMap
      );
    } else {
      console.log('');
      console.log(`   ${c.warning('ℹ')} Bundle creation disabled ${c.dim('(createBundles: false)')} - reporting only`);
    }

    // Summary
    console.log('');
    console.log(`   ${c.dim('─'.repeat(50))}`);
    if (createdBundles.length > 0) {
      console.log(`   ${c.success('✅')} ${c.data('Role Mining Complete!')}`);
      console.log(`      ${c.label('Bundles Created:')} ${c.success(createdBundles.length)}`);
      console.log(`      ${c.label('Users Covered:')} ${c.data(analysis.coverage.usersInRoles)} ${c.dim(`(${analysis.coverage.percentage.toFixed(1)}%)`)}`);
    } else if (!createBundlesEnabled) {
      console.log(`   ${c.success('✓')} ${c.data('Role Mining Analysis Complete')}`);
      console.log(`      ${c.label('Roles Identified:')} ${c.data(analysis.roleCandidates.length)}`);
      console.log(`      ${c.label('Potential Coverage:')} ${c.data(analysis.coverage.usersInRoles)} users ${c.dim(`(${analysis.coverage.percentage.toFixed(1)}%)`)}`);
    } else {
      console.log(`   ${c.warning('⚠')} Role Mining Complete: ${c.error('0 bundles created')} ${c.dim('(see errors above)')}`);
    }

    return {
      bundlesCreated: createdBundles.length,
      usersCovered: analysis.coverage.usersInRoles,
      coveragePercentage: analysis.coverage.percentage,
      totalCandidates: analysis.roleCandidates.length
    };

  } catch (error) {
    console.log('');
    console.log(`   ${c.error('✗')} Role mining failed: ${c.error(error.message)}`);
    throw error;
  }
}
