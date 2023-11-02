import EResult from '../enums-steam/EResult';

/**
 * @hidden
 */
export interface ApiRequest {
    apiInterface: string;
    apiMethod: string;
    apiVersion: number;
    accessToken?: string;
    requestData?: any;
    headers?: any;
}

/**
 * @hidden
 */
export interface ApiResponse {
    result?: EResult;
    errorMessage?: string;
    responseData?: any;
}

/**
 * You can define your own custom transport to communicate with the Steam auth server. If you don't, then steam-session
 * will automatically select an appropriate transport depending on the token platform type.
 *
 * **You almost definitely don't need to do this.** This is used by steam-user to communicate with the auth server over
 * the same channel as the rest of its network communication. Unless this matches your use-case, I cannot think of any
 * reason why you'd need to implement your own custom transport unless you for some reason need to tunnel requests over
 * an entirely different network protocol. If you simply need to proxy requests, you should instead use
 * {@link ConstructorOptions.httpProxy}, {@link ConstructorOptions.socksProxy}, or {@link ConstructorOptions.agent}.
 *
 * If you do need to implement ITransport, it will be helpful to review
 * [ITransport.ts](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/transports/ITransport.ts).
 */
export default interface ITransport {
    /**
     * Sends a request to Steam.
     *
     * @param {ApiRequest} request
     * @return {Promise<ApiResponse>}
     */
    sendRequest(request: ApiRequest): Promise<ApiResponse>;

    /**
     * Cleans up any resources allocated by the transport.
     */
    close(): void;
}
