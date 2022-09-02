import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';

export interface StartLoginSessionWithCredentialsDetails {
	accountName: string;
	password: string;
	deviceFriendlyName?: string;
	persistence?: ESessionPersistence;
	websiteId?: string;
	steamGuardMachineToken?: string;
	steamGuardCode?: string;
}

export interface StartSessionResponse {
	actionRequired: boolean;
	validActions?: StartSessionResponseValidAction[];
}

export interface StartSessionResponseValidAction {
	type: EAuthSessionGuardType;
	detail?: string;
}
