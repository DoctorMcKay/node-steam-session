/**
 * Definitions in this category are only used as input or output from other methods in steam-session.
 * You shouldn't really need to check these docs directly; you'll get linked to relevant pages in this section within
 * the main steam-session section.
 *
 * @module method-params
 */

import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import EAuthSessionSecurityHistory from './enums-steam/EAuthSessionSecurityHistory';
import ITransport from './transports/ITransport';

export interface ConstructorOptions {
	transport?: ITransport,
	socksProxy?: string,
	httpProxy?: string
}

export interface StartLoginSessionWithCredentialsDetails {
	accountName: string;
	password: string;
	persistence?: ESessionPersistence;
	steamGuardMachineToken?: string|Buffer;
	steamGuardCode?: string;
}

export interface StartSessionResponse {
	actionRequired: boolean;
	validActions?: StartSessionResponseValidAction[];

	// The following is for QR logins
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
