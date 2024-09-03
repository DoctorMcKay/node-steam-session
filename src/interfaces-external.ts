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
	 *
	 * If you specify a custom transport, then you are responsible for handling proxy or agent usage in your transport.
	 */
	transport?: ITransport;

	/**
	 * A string containing the local IP address you want to use. For example, `11.22.33.44`.
	 * Cannot be used alongside {@link ConstructorOptions.socksProxy}, {@link ConstructorOptions.httpProxy}, or
	 * {@link ConstructorOptions.agent}.
	 */
	localAddress?: string;

	/**
	 * A string containing a URI for a SOCKS proxy. For example, `socks5://user:pass@1.2.3.4:1080`.
	 * Cannot be used alongside {@link ConstructorOptions.localAddress}, {@link ConstructorOptions.httpProxy}, or
	 * {@link ConstructorOptions.agent}.
	 */
	socksProxy?: string;

	/**
	 * A string containing a URI for an HTTP proxy. For example, `http://user:pass@1.2.3.4:80`.
	 * Cannot be used alongside {@link ConstructorOptions.localAddress}, {@link ConstructorOptions.socksProxy}, or
	 * {@link ConstructorOptions.agent}.
	 */
	httpProxy?: string;

	/**
	 * An `https.Agent` instance to use for requests. If omitted, a new `https.Agent` will be created internally.
	 * Cannot be used alongside {@link ConstructorOptions.localAddress}, {@link ConstructorOptions.socksProxy}, or
	 * {@link ConstructorOptions.httpProxy}.
	 */
	agent?: HTTPS.Agent;

	/**
	 * A string containing the user-agent you want to use when communicating with Steam.
	 * Only effective when using {@link EAuthTokenPlatformType.WebBrowser | EAuthTokenPlatformType.WebBrowser}.
	 */
	userAgent?: string;

	/**
	 * Your Steam machine ID, used for SteamClient logins. Pass a Buffer containing your well-formed machine ID, pass
	 * `true` to have steam-session internally generate a machine ID using the same formula that steam-user uses by
	 * default, or pass `false`, `null`, or omit to not send a machine ID.
	 */
	machineId?: Buffer|boolean;

	/**
	 * Your machine's friendly name. Only effective when using {@link EAuthTokenPlatformType.SteamClient}. If omitted,
	 * a random machine name in the format DESKTOP-ABCDEFG will be generated automatically.
	 */
	machineFriendlyName?: string;
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
	/**
	 * The origin IP address of the QR login attempt
	 */
	ip: string;
	location: {
		/**
		 * A string containing geo coordinates
		 */
		geoloc: string;
		city: string;
		state: string;
	}
	/**
	 * The {@link EAuthTokenPlatformType} provided for the QR code
	 */
	platformType: EAuthTokenPlatformType;
	/**
	 * The device name provided when the QR code was generated (likely a browser user-agent string)
	 */
	deviceFriendlyName: string;
	/**
	 * The version from the QR code. Probably not useful to you.
	 */
	version: number;
	loginHistory: EAuthSessionSecurityHistory;
	/**
	 * Indicates whether the location you requested the auth session info from doesn't match the location where the QR
	 * code was generated
	 */
	locationMismatch: boolean;
	/**
	 * Indicates "whether this login has seen high usage recently"
	 */
	highUsageLogin: boolean;
	/**
	 * The {@link ESessionPersistence} requested for this login
	 */
	requestedPersistence: ESessionPersistence;
}

export interface ApproveAuthSessionRequest {
	/**
	 * A `string` containing the QR challenge URL from a {@link steam-session.LoginSession.startWithQR} call
	 */
	qrChallengeUrl: string;
	/**
	 * `true` to approve the login, or `false` to deny
	 */
	approve: boolean;
	persistence?: ESessionPersistence;
}
