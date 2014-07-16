package com.nimbusds.oauth2.sdk.client;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Client information response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *  "registration_access_token"  : "reg-23410913-abewfq.123483",
 *  "registration_client_uri"    : "https://server.example.com/register/s6BhdRkqt3",
 *  "client_id"                  : "s6BhdRkqt3",
 *  "client_secret"              : "cf136dc3c1fc93f31185e5885805d",
 *  "client_id_issued_at"        : 2893256800
 *  "client_secret_expires_at"   : 2893276800
 *  "client_name"                : "My Example Client",
 *  "client_name#ja-Jpan-JP"     : "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
 *  "redirect_uris"              : [ "https://client.example.org/callback",
 *                                   "https://client.example.org/callback2" ]
 *  "scope"                      : "read write dolphin",
 *  "grant_types"                : [ "authorization_code", "refresh_token" ]
 *  "token_endpoint_auth_method" : "client_secret_basic",
 *  "logo_uri"                   : "https://client.example.org/logo.png",
 *  "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol
 *         (draft-ietf-oauth-dyn-reg-management-02), section 3.1.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol
 *         (draft-ietf-oauth-dyn-reg-18), section 2.
 * </ul>
 */
@Immutable
public class ClientInformationResponse 
	extends ClientRegistrationResponse
	implements SuccessResponse {


	/**
	 * The client information.
	 */
	private ClientInformation clientInfo;


	/**
	 * Creates a new client information response.
	 *
	 * @param clientInfo The client information. Must not be {@code null}.
	 */
	public ClientInformationResponse(final ClientInformation clientInfo) {

		if (clientInfo == null)
			throw new IllegalArgumentException("The client information must not be null");

		this.clientInfo = clientInfo;
	}


	/**
	 * Gets the client information.
	 *
	 * @return The client information.
	 */
	public ClientInformation getClientInformation() {

		return clientInfo;
	}


	@Override
	public HTTPResponse toHTTPResponse() {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		httpResponse.setContent(clientInfo.toJSONObject().toString());
		return httpResponse;
	}


	/**
	 * Parses a client information response from the specified 
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The client information response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        client information response.
	 */
	public static ClientInformationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK, HTTPResponse.SC_CREATED);
		ClientInformation clientInfo = ClientInformation.parse(httpResponse.getContentAsJSONObject());
		return new ClientInformationResponse(clientInfo);
	}
}