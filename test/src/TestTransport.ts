import * as assert from 'assert';

import {ApiRequest, ApiResponse, ITransport} from '../../src';
import {protobufDecodeRequest, protobufEncodeResponse} from './helpers';

export const DONT_CHECK_PROPERTY = Symbol('DON\'T CHECK PROPERTY');

export default class TestTransport implements ITransport {
	closed = false;
	responder:(request: ApiRequest) => ApiResponse = null;

	_requests:ApiRequest[] = [];

	/**
	 * @param {ApiRequest} expected - requestData should NOT be protobuf encoded
	 * @param {boolean} [checkHeaders=false]
	 */
	requestWasMade(expected: ApiRequest, checkHeaders = false): boolean {
		return this._requests.some(req => requestsEqual(expected, req, checkHeaders));
	}

	sendRequest(request: ApiRequest): Promise<ApiResponse> {
		this._requests.push(request);
		let response = this.responder(request);
		if (response.responseData) {
			response.responseData = protobufEncodeResponse(request, response.responseData);
		}
		return new Promise(resolve => resolve(response));
	}

	close(): void {
		this.closed = true;
	}
}

function requestsEqual(expected: ApiRequest, actual: ApiRequest, checkHeaders = false): boolean {
	let props = ['apiInterface', 'apiMethod', 'apiVersion'];
	for (let i = 0; i < props.length; i++) {
		let prop = props[i];
		if (expected[prop] !== actual[prop]) {
			return false;
		}
	}

	if (checkHeaders && !deepEqual(expected.headers, actual.headers)) {
		return false;
	}

	let decodedReq = protobufDecodeRequest(actual);

	for (let i in expected.requestData) {
		if (expected.requestData[i] === DONT_CHECK_PROPERTY) {
			// Don't check the value of this property.
			delete expected.requestData[i];
			delete decodedReq[i];
		}
	}

	return deepEqual(expected.requestData, decodedReq);
}

function deepEqual(obj1, obj2): boolean {
	try {
		assert.deepStrictEqual(obj1, obj2);
		return true;
	} catch {
		return false;
	}
}
