import {createInterface} from 'readline';
import {EAuthSessionGuardType, LoginSession} from '../src';

main();
async function main() {
	let accountName = await promptAsync('Username: ');
	let password = await promptAsync('Password: ');

	let session = new LoginSession();
	await session.startWithCredentials({
		accountName,
		password
	});

	session.on('authSessionGuardRequired', async (type, data) => {
		switch (type) {
			case EAuthSessionGuardType.EmailCode:
				console.log(`An email has been sent to your address at ${data.domain}`);
				await session.submitSteamGuardCode(await promptAsync('Code: '));
				break;

			case EAuthSessionGuardType.DeviceCode:
				console.log('A mobile authenticator code is required');
				await session.submitSteamGuardCode(await promptAsync('Code: '));
				break;

			case EAuthSessionGuardType.EmailConfirmation:
				console.log('You must confirm this login by email');
				break;

			case EAuthSessionGuardType.DeviceConfirmation:
				console.log('Please respond to the prompt in your Steam mobile app');
				break;
		}
	});

	session.on('authenticated', () => {
		console.log('Authenticated successfully! Printing your tokens now...');
		console.log(`SteamID: ${session.steamID}`);
		console.log(`Account name: ${session.accountName}`);
		console.log(`Access token: ${session.accessToken}`);
		console.log(`Refresh token: ${session.refreshToken}`);
	});
}

function promptAsync(question): Promise<string> {
	return new Promise((resolve) => {
		let rl = createInterface({
			input: process.stdin,
			output: process.stdout
		});

		rl.question(question, (result) => {
			rl.close();
			resolve(result);
		});
	});
}
