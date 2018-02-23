export interface OAuth2Options {
    loginUrl?: string;
    clientId?: string;
    clientSecret?: string;
    redirectUri?: string;
}
export interface TokenResponse {
    access_token: string;
    refresh_token: string;
}
export class OAuth2 {
    constructor(options: OAuth2Options)
    public getAuthorizationUrl(params: { scope?: string, response_type?: string, client_id?: string, redirect_uri?: string }): string;
}