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
 * ```js
 * import type {ITransport, ApiRequest, ApiResponse} from 'steam-session';
 * ```
 *
 * It's possible to define a custom transport to be used when interacting with the Steam login server. The default
 * transport used to interact with the Steam login server is chosen depending on your provided
 * {@link steam-session.EAuthTokenPlatformType}.
 *
 * For the {@link steam-session.EAuthTokenPlatformType.SteamClient} platform type, a
 * [WebSocketCMTransport](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/transports/WebSocketCMTransport.ts)
 * will be used to communicate with a CM server using a WebSocket. For other platform types, a
 * [WebApiTransport](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/transports/WebApiTransport.ts)
 * will be used to interact with the Steam login server using api.steampowered.com.
 *
 * **You almost definitely don't need to do this.** This is used by steam-user to communicate with the auth server over
 * the same channel as the rest of its network communication. Unless this matches your use-case, I cannot think of any
 * reason why you'd need to implement your own custom transport unless you for some reason need to tunnel requests over
 * an entirely different network protocol. If you simply need to proxy requests, you should instead use
 * {@link method-params.ConstructorOptions.httpProxy}, {@link method-params.ConstructorOptions.socksProxy}, or
 * {@link method-params.ConstructorOptions.agent}.
 *
 * @see [ITransport.ts](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/transports/ITransport.ts)
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
