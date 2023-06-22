// The following line should be `import {...} from 'steam-session';` if installed from npm
import {EAuthSessionGuardType, EAuthTokenPlatformType, LoginSession} from '../src/index';
import {generateAuthCode} from 'steam-totp';
import {HttpClient, CookieJar} from '@doctormckay/stdlib/http';

const config = {
	accountName: 'username',
	password: 'password',
	sharedSecret: 'shared_secret',
};

async function loginToSteamPartner(session) {
	// We can also get web cookies now that we've negotiated a session
	let webCookies = await session.getWebCookies();

	let jar = new CookieJar();
	webCookies.forEach(cookie => jar.add(cookie, 'partner.steamgames.com'));

	let client = new HttpClient({cookieJar: jar});
	let result = await client.request({
		method: 'GET',
		url: 'https://partner.steamgames.com'
	});

	console.log('Authenticated to partner site?', result.textBody.includes('javascript:Logout()'));
}

(async () => {
	let {accountName, password, sharedSecret} = config;
	let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
	let startResult = await session.startWithCredentials({
		accountName,
		password,
	});

	if (startResult.actionRequired && startResult.validActions.some(action => action.type === EAuthSessionGuardType.DeviceCode)) {
		try {
			let code = generateAuthCode(sharedSecret);
			await session.submitSteamGuardCode(code);
		} catch (ex) {
			console.log(`ERROR: Failure when submitting Steam Guard code: ${ex.message}`);
			process.exit(1);
		}
	} else if (startResult.actionRequired) {
		throw new Error('Login action is required, but we don\'t know how to handle it');
	}

	session.on('authenticated', async () => {
		console.log(`Successfully logged in as ${session.accountName}`);
		loginToSteamPartner(session);
	});

	session.on('timeout', () => {
		console.log('This login attempt has timed out.');
	});

	session.on('error', (err) => {
		// This should ordinarily not happen. This only happens in case there's some kind of unexpected error while
		// polling, e.g. the network connection goes down or Steam chokes on something.
		console.log(`ERROR: This login attempt has failed! ${err.message}`);
	});
})();
