import {createInterface} from 'readline';
import {EAuthSessionGuardType, EAuthTokenPlatformType, LoginSession} from '../src'; // use the following line if you installed the module from npm
//import {EAuthSessionGuardType, LoginSession} from 'steam-session';

// Create a variable where we can store an abort function to cancel stdin input
let g_AbortPromptFunc;

// We need to wrap everything in an async function since node <14.8 cannot use await in the top-level context
main();
async function main() {
	// Prompt for credentials from the console
	let accountName = await promptAsync('Username: ');
	let password = await promptAsync('Password: ', true);

	// Create our LoginSession and start a login session using our credentials. This session will be for a web login.
	let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
	let startResult = await session.startWithCredentials({
		accountName,
		password
	});

	// actionRequired will be true if we need to do something to finish logging in, e.g. supply a code or approve a
	// prompt on our phone.
	if (startResult.actionRequired) {
		console.log('Action is required from you to complete this login');

		// We want to process the non-prompting guard types first, since the last thing we want to do is prompt the
		// user for input. It would be needlessly confusing to prompt for input, then print more text to the console.
		let promptingGuardTypes = [EAuthSessionGuardType.EmailCode, EAuthSessionGuardType.DeviceCode];
		let promptingGuards = startResult.validActions.filter(action => promptingGuardTypes.includes(action.type));
		let nonPromptingGuards = startResult.validActions.filter(action => !promptingGuardTypes.includes(action.type));

		let printGuard = async ({type, detail}) => {
			let code;

			switch (type) {
				case EAuthSessionGuardType.EmailCode:
					console.log(`A login code has been sent to your email address at ${detail}`);
					code = await promptAsync('Code: ');
					if (code) {
						await session.submitSteamGuardCode(code);
					}
					break;

				case EAuthSessionGuardType.DeviceCode:
					console.log('You may confirm this login by providing a Steam Guard Mobile Authenticator code');
					code = await promptAsync('Code: ');
					if (code) {
						await session.submitSteamGuardCode(code);
					}
					break;

				case EAuthSessionGuardType.EmailConfirmation:
					console.log('You may confirm this login by email');
					break;

				case EAuthSessionGuardType.DeviceConfirmation:
					console.log('You may confirm this login by responding to the prompt in your Steam mobile app');
					break;
			}
		};

		nonPromptingGuards.forEach(printGuard);
		promptingGuards.forEach(printGuard);
	}

	session.on('authenticated', async () => {
		abortPrompt();

		console.log('Authenticated successfully! Printing your tokens now...');
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
		abortPrompt();

		console.log('This login attempt has timed out.');
	});

	session.on('error', (err) => {
		abortPrompt();

		// This should ordinarily not happen. This only happens in case there's some kind of unexpected error while
		// polling, e.g. the network connection goes down or Steam chokes on something.
		console.log(`ERROR: This login attempt has failed! ${err.message}`);
	});
}

// Nothing interesting below here, just code for prompting for input from the console.

function promptAsync(question, sensitiveInput = false): Promise<string> {
	return new Promise((resolve) => {
		let rl = createInterface({
			input: process.stdin,
			output: sensitiveInput ? null : process.stdout,
			terminal: true
		});

		g_AbortPromptFunc = () => {
			rl.close();
			resolve('');
		};

		if (sensitiveInput) {
			// We have to write the question manually if we didn't give readline an output stream
			process.stdout.write(question);
		}

		rl.question(question, (result) => {
			if (sensitiveInput) {
				// We have to manually print a newline
				process.stdout.write('\n');
			}

			g_AbortPromptFunc = null;
			rl.close();
			resolve(result);
		});
	});
}

function abortPrompt() {
	if (!g_AbortPromptFunc) {
		return;
	}

	g_AbortPromptFunc();
	process.stdout.write('\n');
}
