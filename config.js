import fs from 'fs';
import readline from 'readline';
import { promisify } from 'util';

const CONFIG_FILE = './config.json';

/**
 * Read configuration from file
 */
export async function loadConfig() {
  try {
    const data = await fs.promises.readFile(CONFIG_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

/**
 * Save configuration to file
 */
export async function saveConfig(config) {
  await fs.promises.writeFile(CONFIG_FILE, JSON.stringify(config, null, 2));
}

/**
 * Prompt user for input
 */
function prompt(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Prompt user to select a CSV file from list
 */
export async function selectCsvFile(csvFiles) {
  console.log('\nMultiple CSV files found. Please select which one to process:\n');

  csvFiles.forEach((file, index) => {
    console.log(`  ${index + 1}. ${file}`);
  });

  console.log('');

  let selectedIndex = -1;
  while (selectedIndex < 1 || selectedIndex > csvFiles.length) {
    const answer = await prompt(`Enter the number (1-${csvFiles.length}): `);
    selectedIndex = parseInt(answer, 10);

    if (isNaN(selectedIndex) || selectedIndex < 1 || selectedIndex > csvFiles.length) {
      console.log(`Invalid selection. Please enter a number between 1 and ${csvFiles.length}.`);
    }
  }

  return csvFiles[selectedIndex - 1];
}

/**
 * Validate and normalize Okta domain
 */
function validateOktaDomain(input) {
  // Clean up: remove protocol and trailing slashes
  let domain = input.trim()
    .replace(/^https?:\/\//, '')
    .replace(/\/+$/, '');

  // Check if it's a valid Okta domain
  const isValidOkta = domain.endsWith('.okta.com') ||
                      domain.endsWith('.oktapreview.com') ||
                      domain === 'okta.com' ||
                      domain === 'oktapreview.com';

  if (!isValidOkta) {
    return {
      valid: false,
      domain: null,
      error: 'Invalid Okta domain. Must end with .okta.com or .oktapreview.com'
    };
  }

  return {
    valid: true,
    domain: domain,
    error: null
  };
}

/**
 * Get configuration interactively from user
 */
export async function getConfigInteractively() {
  console.log('\nConfiguration file not found. Please provide the following information:\n');

  let oktaDomain;
  let isValid = false;

  // Keep prompting until we get a valid Okta domain
  while (!isValid) {
    const input = await prompt('Okta Tenant URL (e.g., your-tenant.okta.com or https://your-tenant.okta.com): ');
    const validation = validateOktaDomain(input);

    if (validation.valid) {
      oktaDomain = validation.domain;
      isValid = true;
      console.log(`✓ Valid Okta domain: ${oktaDomain}`);
    } else {
      console.log(`✗ ${validation.error}`);
      console.log('  Please enter a valid Okta domain (e.g., your-tenant.okta.com)\n');
    }
  }

  console.log('');
  console.log('Authentication Method:');
  console.log('  OAuth 2.0 Client Credentials (Recommended) provides scoped access');
  console.log('');

  const clientId = await prompt('OAuth Client ID: ');
  const clientSecret = await prompt('OAuth Client Secret: ');

  const config = {
    oktaDomain: oktaDomain,
    clientId: clientId.trim(),
    clientSecret: clientSecret.trim()
  };

  await saveConfig(config);
  console.log(`\nConfiguration saved to ${CONFIG_FILE}\n`);

  return config;
}

/**
 * Get OAuth access token using client credentials flow
 */
export async function getAccessToken(config) {
  // Required scopes for all app operations
  // Note: These scopes must be granted to the OAuth client in Okta Admin Console
  const scopes = [
    'okta.apps.manage',
    'okta.apps.read',
    'okta.schemas.manage',
    'okta.schemas.read',
    'okta.users.read',
    'okta.profileMappings.manage',
    'okta.profileMappings.read',
    'okta.governance.entitlements.manage',
    'okta.governance.entitlements.read',
    'okta.governance.resources.manage',
    'okta.governance.resources.read'
  ];

  const tokenUrl = `https://${config.oktaDomain}/oauth2/v1/token`;

  // Encode client credentials for Basic Auth
  const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');

  try {
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: scopes.join(' ')
      })
    });

    if (!response.ok) {
      const errorBody = await response.text();

      // Check if it's a scope error
      if (errorBody.includes('invalid_scope') || errorBody.includes('Custom scopes')) {
        throw new Error(
          `OAuth client missing required scopes. Please grant these scopes in Okta Admin Console:\n` +
          `  Applications → OAuth Applications → ${config.clientId} → Okta API Scopes\n` +
          `  Required scopes:\n    ` + scopes.join('\n    ') +
          `\n\nOriginal error: ${errorBody}`
        );
      }

      throw new Error(`Failed to get access token: ${response.status} - ${errorBody}`);
    }

    const tokenData = await response.json();
    return tokenData.access_token;
  } catch (error) {
    throw new Error(`OAuth token request failed: ${error.message}`);
  }
}

/**
 * Get configuration from file or prompt user
 */
export async function getConfig() {
  let config = await loadConfig();

  if (!config) {
    config = await getConfigInteractively();
  } else {
    // Validate existing config
    const validation = validateOktaDomain(config.oktaDomain);
    if (!validation.valid) {
      console.log(`\n⚠️  Warning: Existing configuration has an invalid Okta domain: ${config.oktaDomain}`);
      console.log(`   ${validation.error}\n`);
      console.log('Please reconfigure:\n');
      config = await getConfigInteractively();
    }

    // Check if we need to migrate from SSWS token to OAuth
    if (config.apiToken && !config.clientId) {
      console.log('\n⚠️  Warning: Configuration uses legacy SSWS token authentication');
      console.log('   For better security and governance access, consider migrating to OAuth 2.0');
      console.log('   Current limitations with SSWS:');
      console.log('     • May not have access to all governance APIs');
      console.log('     • Less granular permission control');
      console.log('');
      const migrate = await prompt('Would you like to migrate to OAuth now? (y/n): ');

      if (migrate.toLowerCase() === 'y' || migrate.toLowerCase() === 'yes') {
        console.log('');
        const clientId = await prompt('OAuth Client ID: ');
        const clientSecret = await prompt('OAuth Client Secret: ');

        config.clientId = clientId.trim();
        config.clientSecret = clientSecret.trim();
        // Keep apiToken as fallback

        await saveConfig(config);
        console.log('\n✓ Configuration updated with OAuth credentials\n');
      }
    }
  }

  return config;
}
