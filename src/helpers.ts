import EResult from './enums-steam/EResult';

function eresultError(result:EResult, errorMessage?:string): Error {
	let resultMsg:string = result.toString();

	for (let i in EResult) {
		if (EResult[i] == result.toString()) {
			resultMsg = i;
			break;
		}
	}

	let err = new Error(errorMessage || resultMsg);
	// @ts-ignore
	err.eresult = result;
	return err;
}

export {eresultError};
