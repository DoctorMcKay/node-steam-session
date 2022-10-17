// This example creates a QR login session, then approves it using a provided access token and shared secret.

import {createInterface} from 'readline';
import {EAuthTokenPlatformType, ESessionPersistence, EAuthSessionSecurityHistory, LoginApprover, LoginSession} from '../src'; // use the following line if you installed the module from npm
//import {EAuthTokenPlatformType, ESessionPersistence, EAuthSessionSecurityHistory, LoginApprover, LoginSession} from 'steam-session';

// We need to wrap everything in an async function since node <14.8 cannot use await in the top-level context
main();
async function main() {
	console.log('In order to approve a QR login attempt, you need an access token (NOT a refresh token) that was created using EAuthTokenPlatformType.MobileApp.');
	console.log('You additionally need the TOTP shared_secret for your account.');

	let accessToken = await promptAsync('Access Token: ');
	let sharedSecret = await promptAsync('Shared Secret: ');

	let approver = new LoginApprover(accessToken, sharedSecret);
	console.log(`We will attempt to log into ${approver.steamID} using the WebBrowser platform.`);

	// Create our LoginSession and start a QR login session.
	let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
	session.loginTimeout = 120000; // timeout after 2 minutes
	let startResult = await session.startWithQR();
	console.log(`QR code url: ${startResult.qrChallengeUrl}`);

	session.on('remoteInteraction', () => {
		console.log('A remote interaction was detected.');
	});

	session.on('authenticated', async () => {
		console.log('\nAuthenticated successfully! Printing your tokens now...');
		console.log(`SteamID: ${session.steamID}`);
		console.log(`Account name: ${session.accountName}`);
		console.log(`Access token: ${session.accessToken}`);
		console.log(`Refresh token: ${session.refreshToken}`);

		// We can also get web cookies now that we've negotiated a session
		let webCookies = await session.getWebCookies();
		console.log('Web session cookies:');
		console.log(webCookies);
	});

	session.on('timeout', () => {
		console.log('This login attempt has timed out.');
	});

	session.on('error', (err) => {
		// This should ordinarily not happen. This only happens in case there's some kind of unexpected error while
		// polling, e.g. the network connection goes down or Steam chokes on something.
		console.log(`ERROR: This login attempt has failed! ${err.message}`);
	});

	// Now that all the LoginSession handlers are set up, we can approve the attempt
	let sessionInfo = await approver.getAuthSessionInfo(startResult.qrChallengeUrl);
	console.log('\n====== LOGIN ATTEMPT INFO ======');
	console.log(`IP: ${sessionInfo.ip}`);
	console.log(`Location: ${sessionInfo.location.city}, ${sessionInfo.location.state} (${sessionInfo.location.geoloc})`);
	console.log(`Platform Type: ${EAuthTokenPlatformType[sessionInfo.platformType]}`);
	console.log(`Device Name: ${sessionInfo.deviceFriendlyName}`);
	console.log(`Login History: ${EAuthSessionSecurityHistory[sessionInfo.loginHistory]}`);
	console.log(`Persistence: ${ESessionPersistence[sessionInfo.requestedPersistence]}`);
	console.log('====== END LOGIN ATTEMPT INFO ======\n');

	console.log('Approving login attempt...');
	await approver.approveAuthSession({
		qrChallengeUrl: startResult.qrChallengeUrl,
		approve: true
	});

	// Now that we've approved the login attempt, we can immediately poll to get our access tokens
	session.forcePoll();
}

// Nothing interesting below here, just code for prompting for input from the console.

function promptAsync(question, sensitiveInput = false): Promise<string> {
	return new Promise((resolve) => {
		let rl = createInterface({
			input: process.stdin,
			output: sensitiveInput ? null : process.stdout,
			terminal: true
		});

		if (sensitiveInput) {
			// We have to write the question manually if we didn't give readline an output stream
			process.stdout.write(question);
		}

		rl.question(question, (result) => {
			if (sensitiveInput) {
				// We have to manually print a newline
				process.stdout.write('\n');
			}

			rl.close();
			resolve(result);
		});
	});
}
