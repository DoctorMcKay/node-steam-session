import {createInterface} from 'readline';
import {EAuthSessionGuardType, LoginSession} from '../src';

let g_AbortPromptFunc;

main();
async function main() {
	let accountName = await promptAsync('Username: ');
	let password = await promptAsync('Password: ', true);

	let session = new LoginSession();
	let startResult = await session.startWithCredentials({
		accountName,
		password
	});

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

		console.log(`ERROR: This login attempt has failed! ${err.message}`);
	});
}

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
