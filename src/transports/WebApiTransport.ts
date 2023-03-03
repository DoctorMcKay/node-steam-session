import axios, {AxiosRequestConfig, AxiosResponse} from 'axios';
import QueryString from 'querystring';

import ITransport, {ApiRequest, ApiResponse} from './ITransport';
import EResult from '../enums-steam/EResult';
import {API_HEADERS} from '../helpers';

// Assume everything is a POST request unless it's specifically listed as a GET request
const GET_REQUESTS = [
	'IAuthenticationService/GetPasswordRSAPublicKey/v1'
];

export default class WebApiTransport implements ITransport {
	async sendRequest(request: ApiRequest): Promise<ApiResponse> {
		let urlPath = `I${request.apiInterface}Service/${request.apiMethod}/v${request.apiVersion}`;

		let requestOptions:AxiosRequestConfig = {
			method: GET_REQUESTS.includes(urlPath) ? 'GET' : 'POST',
			url: `https://api.steampowered.com/${urlPath}`,
			headers: {...API_HEADERS, ...(request.headers || {})},
			responseType: 'arraybuffer'
		};

		let queryString:any = {};
		let form:any = {};

		if (request.accessToken) {
			queryString.access_token = request.accessToken;
		}

		if (request.requestData && request.requestData.length > 0) {
			(requestOptions.method == 'GET' ? queryString : form).input_protobuf_encoded = request.requestData.toString('base64');
		}

		if (Object.keys(queryString).length > 0) {
			requestOptions.url += '?' + QueryString.stringify(queryString);
		}

		if (Object.keys(form).length > 0) {
			requestOptions.headers['content-type'] = 'multipart/form-data';
			requestOptions.data = form;
		}

		let result:AxiosResponse = await axios(requestOptions);
		let apiResponse:ApiResponse = {};

		let eresultHeader = result.headers['x-eresult'];
		let errorMessageHeader = result.headers['x-error_message'];

		if (typeof eresultHeader == 'string') {
			apiResponse.result = parseInt(eresultHeader) as EResult;
		}

		if (typeof errorMessageHeader == 'string') {
			apiResponse.errorMessage = errorMessageHeader;
		}

		if (result.data && result.data.length > 0) {
			apiResponse.responseData = result.data;
		}

		return apiResponse;
	}

	// eslint-disable-next-line @typescript-eslint/no-empty-function
	close() {}
}
