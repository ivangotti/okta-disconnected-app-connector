import fs from 'fs';
import readline from 'readline';
import { promisify } from 'util';
import * as jose from 'jose';

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
  console.log('API Token Setup:');
  console.log('  Create an API token in Okta Admin Console:');
  console.log('  Security → API → Tokens → Create Token');
  console.log('');

  const apiToken = await prompt('Okta API Token (SSWS): ');

  const config = {
    oktaDomain: oktaDomain,
    apiToken: apiToken.trim()
  };

  await saveConfig(config);
  console.log(`\nConfiguration saved to ${CONFIG_FILE}\n`);

  return config;
}

/**
 * Generate client assertion JWT for private_key_jwt authentication
 */
async function generateClientAssertion(config, tokenUrl) {
  // Read private key from file or use inline key
  let privateKeyPem;

  if (config.privateKeyPath) {
    privateKeyPem = await fs.promises.readFile(config.privateKeyPath, 'utf8');
  } else if (config.privateKey) {
    privateKeyPem = config.privateKey;
  } else {
    throw new Error('Private key not found in configuration. Provide either privateKeyPath or privateKey.');
  }

  // Import the private key
  const privateKey = await jose.importPKCS8(privateKeyPem, 'RS256');

  // Create JWT claims
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: config.clientId,
    sub: config.clientId,
    aud: tokenUrl,
    exp: now + 300, // 5 minutes expiration
    iat: now,
    jti: `${config.clientId}-${now}-${Math.random().toString(36).substring(2)}`
  };

  // Sign the JWT
  const jwt = await new jose.SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);

  return jwt;
}

/**
 * Get OAuth access token using client credentials flow
 */
export async function getAccessToken(config) {
  // For Okta Management APIs, scopes are pre-granted in Admin Console
  // We don't request specific scopes in the token request - Okta will include
  // all scopes that were granted to this client in the Admin Console
  const tokenUrl = `https://${config.oktaDomain}/oauth2/v1/token`;

  try {
    console.log(`   → Requesting OAuth token from: ${tokenUrl}`);
    console.log(`   → Client ID: ${config.clientId}`);

    // Check which authentication method to use
    const usePrivateKeyJwt = config.privateKey || config.privateKeyPath;

    let headers;
    let bodyParams;

    if (usePrivateKeyJwt) {
      // Use private_key_jwt authentication
      console.log(`   → Authentication method: private_key_jwt`);
      const clientAssertion = await generateClientAssertion(config, tokenUrl);

      headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
      };

      bodyParams = {
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: clientAssertion,
        scope: 'okta.apps.manage okta.apps.read okta.users.manage okta.users.read okta.schemas.manage okta.schemas.read okta.profileMappings.manage okta.profileMappings.read okta.governance.accessCertifications.manage okta.governance.accessRequests.manage'
      };
    } else if (config.clientSecret) {
      // Use client_secret_basic authentication
      console.log(`   → Authentication method: client_secret_basic`);
      const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');

      headers = {
        'Authorization': `Basic ${credentials}`,
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
      };

      bodyParams = {
        grant_type: 'client_credentials',
        scope: 'okta.apps.manage okta.apps.read okta.users.manage okta.users.read okta.schemas.manage okta.schemas.read okta.profileMappings.manage okta.profileMappings.read okta.governance.accessCertifications.manage okta.governance.accessRequests.manage'
      };
    } else {
      throw new Error('No authentication credentials found. Provide either privateKey/privateKeyPath or clientSecret.');
    }

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: headers,
      body: new URLSearchParams(bodyParams)
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.log(`   ✗ Token request failed: ${response.status}`);
      console.log(`   → Response: ${errorBody}`);

      let errorData;

      try {
        errorData = JSON.parse(errorBody);
      } catch (e) {
        errorData = { error_description: errorBody };
      }

      // Provide helpful error messages
      if (errorData.error === 'invalid_client') {
        // Check if it's the application_type issue
        if (errorData.error_description && errorData.error_description.includes('application_type')) {
          throw new Error(
            `❌ OAuth Application Type Mismatch!\n\n` +
            `The OAuth application (${config.clientId}) must be created as "API Services" type.\n\n` +
            `Current error: ${errorData.error_description}\n\n` +
            `To fix this:\n` +
            `  1. Login to Okta Admin Console (https://${config.oktaDomain})\n` +
            `  2. Navigate to Applications → Applications\n` +
            `  3. Create a NEW app integration:\n` +
            `     - Click "Create App Integration"\n` +
            `     - Select "API Services" (NOT Web, Native, or SPA)\n` +
            `     - Give it a name (e.g., "CSV Agent")\n` +
            `     - Click Save\n` +
            `  4. Copy the new Client ID and Client Secret\n` +
            `  5. Update your config.json with the new credentials\n` +
            `  6. Grant required Okta API Scopes in the "Okta API Scopes" tab\n\n` +
            `Note: The current client ${config.clientId} appears to be the wrong type\n` +
            `(e.g., Web, Native, or SPA application instead of API Services).`
          );
        }

        throw new Error(
          `Invalid OAuth client credentials.\n` +
          `Please verify in Okta Admin Console:\n` +
          `  1. Navigate to Applications → Applications\n` +
          `  2. Find the OAuth application: ${config.clientId}\n` +
          `  3. Verify the Client Secret matches\n` +
          `  4. Ensure the app is ACTIVE\n` +
          `  5. Check that it's an "API Services" application type\n\n` +
          `Original error: ${errorData.error_description || errorBody}`
        );
      }

      throw new Error(`Failed to get access token: ${response.status} - ${errorBody}`);
    }

    const tokenData = await response.json();

    // Log the scopes we received for debugging
    console.log('   ✓ OAuth token acquired successfully');
    if (tokenData.scope) {
      console.log(`   → Granted scopes: ${tokenData.scope}`);
    }

    return tokenData.access_token;
  } catch (error) {
    throw new Error(`OAuth token request failed: ${error.message}`);
  }
}

/**
 * Reconfigure credentials when they are missing or invalid
 * Prompts for API token (recommended for full API compatibility)
 */
export async function reconfigureOAuthCredentials() {
  console.log('\n' + '='.repeat(70));
  console.log('⚠️  Authentication Configuration Required');
  console.log('='.repeat(70));

  const existingConfig = await loadConfig();

  if (!existingConfig) {
    // No config at all, do full interactive setup
    return await getConfigInteractively();
  }

  console.log(`\n   Current configuration:`);
  console.log(`   • Okta Domain: ${existingConfig.oktaDomain || '(not set)'}`);
  console.log(`   • API Token: ${existingConfig.apiToken ? '(set)' : '(not set)'}`);

  if (existingConfig.clientId) {
    console.log(`   • Client ID: ${existingConfig.clientId} (OAuth - not recommended)`);
  }

  console.log('\n   ℹ️  API Token is recommended for full Okta API compatibility.');
  console.log('   The Governance APIs work best with SSWS API tokens.\n');

  console.log('   To create an API token:');
  console.log('   1. Login to Okta Admin Console');
  console.log('   2. Navigate to: Security → API → Tokens');
  console.log('   3. Click "Create Token" and give it a name');
  console.log('   4. Copy the token value (shown only once)\n');

  const apiToken = await prompt('Okta API Token (SSWS): ');

  // Set API token and remove OAuth settings
  existingConfig.apiToken = apiToken.trim();
  delete existingConfig.clientId;
  delete existingConfig.clientSecret;
  delete existingConfig.privateKey;
  delete existingConfig.privateKeyPath;

  await saveConfig(existingConfig);
  console.log('\n   ✓ API Token saved to config.json');
  console.log('   ✓ OAuth settings removed (using API Token only)\n');

  return existingConfig;
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

  }

  // Set role mining defaults if not specified
  if (!config.roleMining) {
    config.roleMining = {
      enabled: true,
      minUserThreshold: 2,
      createBundles: true,
      syncMode: 'initial'
    };
  } else {
    // Fill in missing defaults
    if (config.roleMining.enabled === undefined) config.roleMining.enabled = true;
    if (config.roleMining.minUserThreshold === undefined) config.roleMining.minUserThreshold = 2;
    if (config.roleMining.createBundles === undefined) config.roleMining.createBundles = true;
    if (config.roleMining.syncMode === undefined) config.roleMining.syncMode = 'initial';
  }

  return config;
}
