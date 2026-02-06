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
  console.log('  1. Device Flow (Recommended) - Authenticate as yourself in browser');
  console.log('  2. Client Credentials - Use OAuth API Services app (requires admin setup)');
  console.log('');

  let authFlow;
  while (!authFlow) {
    const flowChoice = await prompt('Select authentication method (1 or 2): ');
    if (flowChoice === '1' || flowChoice === '2') {
      authFlow = flowChoice === '1' ? 'device' : 'client_credentials';
    } else {
      console.log('Invalid choice. Please enter 1 or 2.');
    }
  }

  console.log('');

  let config;

  if (authFlow === 'device') {
    console.log('Device Flow Setup:');
    console.log('  You need a Native or SPA OAuth application (any type except API Services)');
    console.log('');

    const clientId = await prompt('OAuth Client ID: ');

    config = {
      oktaDomain: oktaDomain,
      authFlow: 'device',
      clientId: clientId.trim()
    };

    console.log('');
    console.log('Note: You will authenticate in your browser when the app runs.');
  } else {
    console.log('Client Credentials Setup:');
    console.log('  Requires an "API Services" OAuth application with pre-granted scopes');
    console.log('');

    const clientId = await prompt('OAuth Client ID: ');
    const clientSecret = await prompt('OAuth Client Secret: ');

    config = {
      oktaDomain: oktaDomain,
      authFlow: 'client_credentials',
      clientId: clientId.trim(),
      clientSecret: clientSecret.trim()
    };
  }

  await saveConfig(config);
  console.log(`\nConfiguration saved to ${CONFIG_FILE}\n`);

  return config;
}

/**
 * Get OAuth access token using device authorization flow
 * This allows user to authenticate in browser and consent to scopes
 */
export async function getAccessTokenDeviceFlow(config) {
  // For Okta Management APIs with device flow, we use standard OpenID scopes
  // The user's Okta admin permissions determine what API operations they can perform
  // Custom Okta Management scopes (okta.apps.manage, etc.) are not allowed in device flow
  const scopes = ['openid', 'profile', 'email', 'okta.users.read'];

  const deviceAuthUrl = `https://${config.oktaDomain}/oauth2/v1/device/authorize`;
  const tokenUrl = `https://${config.oktaDomain}/oauth2/v1/token`;

  try {
    // Step 1: Request device code
    console.log('   → Requesting device authorization code...');
    console.log(`   → Device auth URL: ${deviceAuthUrl}`);
    console.log(`   → Client ID: ${config.clientId}`);
    console.log(`   → Authentication: Device flow uses your Okta admin permissions`);

    const deviceResponse = await fetch(deviceAuthUrl, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: config.clientId,
        scope: scopes.join(' ')
      })
    });

    if (!deviceResponse.ok) {
      const errorBody = await deviceResponse.text();
      let errorData;

      try {
        errorData = JSON.parse(errorBody);
      } catch (e) {
        errorData = { error_description: errorBody };
      }

      // Provide helpful error messages
      if (errorData.error === 'invalid_client') {
        throw new Error(
          `❌ OAuth Client Not Found or Device Flow Not Enabled!\n\n` +
          `Client ID: ${config.clientId}\n\n` +
          `The OAuth application must support Device Authorization Flow.\n\n` +
          `To fix this:\n` +
          `  1. Login to Okta Admin Console (https://${config.oktaDomain})\n` +
          `  2. Navigate to Applications → Applications\n` +
          `  3. Find or create an OAuth application:\n` +
          `     - Application type: Native or Single-Page App (SPA)\n` +
          `     - Grant type: Device Authorization (must be enabled)\n` +
          `  4. In the application settings:\n` +
          `     - Go to General Settings\n` +
          `     - Scroll to "Grant type"\n` +
          `     - Check "Device Authorization"\n` +
          `     - Click Save\n` +
          `  5. Copy the Client ID\n` +
          `  6. Update your config.json with the new Client ID\n\n` +
          `Original error: ${errorData.error_description}`
        );
      }

      throw new Error(`Device authorization request failed: ${deviceResponse.status} - ${errorBody}`);
    }

    const deviceData = await deviceResponse.json();

    // Step 2: Display instructions to user
    console.log('');
    console.log('   ╔════════════════════════════════════════════════════════════════╗');
    console.log('   ║                   USER AUTHENTICATION REQUIRED                 ║');
    console.log('   ╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`   🌐 Please visit: ${deviceData.verification_uri}`);
    console.log('');
    console.log(`   🔑 Enter code: ${deviceData.user_code}`);
    console.log('');
    console.log('   ⏱  Waiting for you to complete authentication...');
    console.log('      (This code expires in ' + Math.floor(deviceData.expires_in / 60) + ' minutes)');
    console.log('');

    // Step 3: Poll for token
    const interval = deviceData.interval || 5; // Default 5 seconds between polls
    const expiresAt = Date.now() + (deviceData.expires_in * 1000);

    while (Date.now() < expiresAt) {
      await new Promise(resolve => setTimeout(resolve, interval * 1000));

      const tokenResponse = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          client_id: config.clientId,
          device_code: deviceData.device_code,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
        })
      });

      if (tokenResponse.ok) {
        const tokenData = await tokenResponse.json();
        console.log('   ✓ Authentication successful!');
        console.log('   ✓ OAuth token acquired');
        if (tokenData.scope) {
          console.log(`   → Granted scopes: ${tokenData.scope}`);
        }
        console.log('');
        return tokenData.access_token;
      }

      const errorData = await tokenResponse.json();

      if (errorData.error === 'authorization_pending') {
        // Still waiting for user to authorize
        process.stdout.write('   ⏳ Still waiting...\r');
        continue;
      }

      if (errorData.error === 'slow_down') {
        // Server wants us to slow down
        await new Promise(resolve => setTimeout(resolve, 5000));
        continue;
      }

      // Any other error is terminal
      throw new Error(`Device authorization failed: ${errorData.error} - ${errorData.error_description}`);
    }

    throw new Error('Device authorization timed out - user did not complete authentication in time');

  } catch (error) {
    throw new Error(`Device flow authentication failed: ${error.message}`);
  }
}

/**
 * Get OAuth access token using client credentials flow
 */
export async function getAccessToken(config) {
  // For Okta Management APIs, scopes are pre-granted in Admin Console
  // We don't request specific scopes in the token request - Okta will include
  // all scopes that were granted to this client in the Admin Console
  const tokenUrl = `https://${config.oktaDomain}/oauth2/v1/token`;

  // Encode client credentials for Basic Auth
  const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');

  try {
    console.log(`   → Requesting OAuth token from: ${tokenUrl}`);
    console.log(`   → Client ID: ${config.clientId}`);

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials'
        // Note: No scope parameter - uses pre-granted scopes from Admin Console
      })
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
