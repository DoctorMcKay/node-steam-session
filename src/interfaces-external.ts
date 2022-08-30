import ESessionPersistence from './enums-steam/ESessionPersistence';

export interface StartLoginSessionWithCredentialsDetails {
	accountName: string;
	password: string;
	deviceFriendlyName?: string;
	persistence?: ESessionPersistence;
	websiteId?: string;
	steamGuardMachineToken?: string;
	steamGuardCode?: string;
}
