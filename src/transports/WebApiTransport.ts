import createDebug from 'debug';
import {HttpClient, HttpRequestOptions} from '@doctormckay/stdlib/http';

import EResult from '../enums-steam/EResult';

import ITransport, {ApiRequest, ApiResponse} from './ITransport';
import {API_HEADERS} from '../helpers';

const debug = createDebug('steam-session:WebApiTransport');

// Assume everything is a POST request unless it's specifically listed as a GET request
const GET_REQUESTS = [
	'IAuthenticationService/GetPasswordRSAPublicKey/v1'
];

const WEBAPI_BASE = 'https://api.steampowered.com';

export interface WebApiTransportOptions {
	httpProxy?: string,
	socksProxy?: string
}

export default class WebApiTransport implements ITransport {
	_client: HttpClient;

	constructor(client: HttpClient) {
		this._client = client;
	}

	async sendRequest(request: ApiRequest): Promise<ApiResponse> {
		let urlPath = `I${request.apiInterface}Service/${request.apiMethod}/v${request.apiVersion}`;
		let url = `${WEBAPI_BASE}/${urlPath}/`;
		let method = GET_REQUESTS.includes(urlPath) ? 'GET' : 'POST';
		let headers = {...API_HEADERS, ...(request.headers || {})};

		let queryString:any = {};
		let form:any = {};

		if (request.accessToken) {
			queryString.access_token = request.accessToken;
		}

		if (request.requestData && request.requestData.length > 0) {
			(method == 'GET' ? queryString : form).input_protobuf_encoded = request.requestData.toString('base64');
		}

		debug('%s %s %o %o', method, url, queryString, form);

		let requestOptions:HttpRequestOptions = {
			method,
			url,
			headers,
			queryString
		};

		if (method == 'POST' && Object.keys(form).length > 0) {
			requestOptions.multipartForm = HttpClient.simpleObjectToMultipartForm(form);
		}

		let result = await this._client.request(requestOptions);

		if (result.statusCode < 200 || result.statusCode >= 300) {
			let err:any = new Error(`WebAPI error ${result.statusCode}`);
			err.code = result.statusCode;
			throw err;
		}

		let apiResponse:ApiResponse = {};

		let eresultHeader = result.headers['x-eresult'];
		let errorMessageHeader = result.headers['x-error_message'];

		if (typeof eresultHeader == 'string') {
			apiResponse.result = parseInt(eresultHeader) as EResult;
		}

		if (typeof errorMessageHeader == 'string') {
			apiResponse.errorMessage = errorMessageHeader;
		}

		let resultBody:any = result.jsonBody || result.textBody || result.rawBody;
		let isMeaningfulJsonBody = result.jsonBody && Object.keys(result.jsonBody).length > 0;
		if (resultBody && (isMeaningfulJsonBody || resultBody.length > 0)) {
			apiResponse.responseData = resultBody;
		}

		return apiResponse;
	}

	// eslint-disable-next-line @typescript-eslint/no-empty-function
	close() {}
}
