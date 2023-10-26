/**
 * Definitions in this category are only used as input or output from other methods in steam-session.
 * You shouldn't really need to check these docs directly; you'll get linked to relevant pages in this section within
 * the main steam-session section.
 *
 * @module method-params
 */

import HTTPS from 'https';

import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import EAuthSessionSecurityHistory from './enums-steam/EAuthSessionSecurityHistory';
import ITransport from './transports/ITransport';

export interface ConstructorOptions {
	/**
	 * An `ITransport` instance, if you need to specify a custom transport. If omitted, defaults to a
	 * `WebSocketCMTransport` instance for `SteamClient` platform types, and a `WebApiTransport` instance for all other
	 * platform types. In all likelihood, you don't need to use this.
	 */
	transport?: ITransport,

	/**
	 * A string containing the local IP address you want to use. For example, '11.22.33.44'.
	 * Cannot be used alongside `socksProxy`, `httpProxy`, or `agent`.
	 */
	localAddress?: string,

	/**
	 * A string containing a URI for a SOCKS proxy. For example, `socks5://user:pass@1.2.3.4:1080`.
	 * Cannot be used alongside `localAddress`, `httpProxy`, or `agent`.
	 */
	socksProxy?: string,

	/**
	 * A string containing a URI for an HTTP proxy. For example, `http://user:pass@1.2.3.4:80`.
	 * Cannot be used alongside `localAddress`, `socksProxy`, or `agent`.
	 */
	httpProxy?: string,

	/**
	 * An `https.Agent` instance to use for requests. If omitted, a new `https.Agent` will be created internally.
	 * Cannot be used alongside `localAddress`, `socksProxy`, or `httpProxy`.
	 */
	agent?: HTTPS.Agent,

	/**
	 * A string containing the user-agent you want to use when communicating with Steam.
	 * Only effective when using EAuthTokenPlatformType.WebBrowser.
	 */
	userAgent?: string,

	/**
	 * Your Steam machine ID, used for SteamClient logins. Pass a Buffer containing your well-formed machine ID, pass
	 * `true` to have steam-session internally generate a machine ID using the same formula that steam-user uses by
	 * default, or pass `false`, `null`, or omit to not send a machine ID.
	 */
	machineId?: Buffer|boolean
}

export interface StartLoginSessionWithCredentialsDetails {
	/**
	 * Your Steam account's login name.
	 */
	accountName: string;

	/**
	 * Your Steam account password.
	 */
	password: string;

	/**
	 * Optional. A value from {@link ESessionPersistence}. Defaults to {@link ESessionPersistence.Persistent}.
	 */
	persistence?: ESessionPersistence;

	/**
	 * Optional. If you have a valid Steam Guard machine token, supplying it here will allow you to bypass email code verification.
	 */
	steamGuardMachineToken?: string|Buffer;

	/**
	 * Optional. If you have a valid Steam Guard code (either email or TOTP), supplying it here will attempt to use it during login.
	 */
	steamGuardCode?: string;
}

export interface StartSessionResponse {
	/**
	 * If this is a response to {@link steam-session.LoginSession.startWithCredentials}:
	 *
	 * A boolean indicating whether action is required from you to continue this login attempt.
	 * If false, you should expect for {@link steam-session.LoginSession.authenticated} to be emitted shortly.
	 */
	actionRequired: boolean;

	/**
	 * If this is a response to {@link steam-session.LoginSession.startWithCredentials}:
	 *
	 * If {@link actionRequired} is true, this is an array of objects indicating which actions you could take to continue this
	 * login attempt. Each object has these properties:
	 *
	 * - {@link StartSessionResponseValidAction.type} - A value from {@link EAuthSessionGuardType}
	 * - {@link StartSessionResponseValidAction.detail} - An optional string containing more details about this guard option. Right now, the only known use
	 *    for this is that it contains your email address' domain for {@link EAuthSessionGuardType.EmailCode}.
	 */
	validActions?: StartSessionResponseValidAction[];

	/**
	 * If this is a response to {@link steam-session.LoginSession.startWithQR}:
	 *
	 * A string containing the URL that should be encoded into a QR code and then scanned with the Steam mobile app.
	 */
	qrChallengeUrl?: string;
}

export interface StartSessionResponseValidAction {
	type: EAuthSessionGuardType;
	detail?: string;
}

export interface AuthSessionInfo {
	ip: string;
	location: {
		geoloc: string;
		city: string;
		state: string;
	}
	platformType: EAuthTokenPlatformType;
	deviceFriendlyName: string;
	version: number;
	loginHistory: EAuthSessionSecurityHistory;
	locationMismatch: boolean;
	highUsageLogin: boolean;
	requestedPersistence: ESessionPersistence;
}

export interface ApproveAuthSessionRequest {
	qrChallengeUrl: string;
	approve: boolean;
	persistence?: ESessionPersistence;
}
