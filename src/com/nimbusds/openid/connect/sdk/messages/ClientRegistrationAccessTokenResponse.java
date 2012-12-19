package com.nimbusds.openid.connect.sdk.messages;


import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.claims.ClientID;

import com.nimbusds.openid.connect.sdk.http.CommonContentTypes;
import com.nimbusds.openid.connect.sdk.http.HTTPResponse;


/**
 * The base class for client associate and rotate secret responses.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 * 
 * {
 *  "client_id"                 : "s6BhdRkqt3",
 *  "client_secret"             : "cf136dc3c1fd9153029bb9c6cc9ecead91",
 *  "registration_access_token" : "this.is.a.access.token.value.ffx83",
 *  "expires_at"                : 2893276800
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-19)
 */
public class ClientRegistrationAccessTokenResponse extends ClientRegistrationResponse {


	/**
	 * The registration access token.
	 */
	private final AccessToken accessToken;


	/**
	 * Optional client secret.
	 */
	private final String clientSecret;


	/**
	 * Optional expiration time.
	 */
	private final long expiresAt;


	/**
	 * Creates a new client registration access token response.
	 *
	 * @param clientID    The client ID. Must not be {@code null}.
	 * @param accessToken The registration access token. Must not be
	 *                    {@code null}.
	 */
	public ClientRegistrationAccessTokenResponse(final ClientID clientID,
		                                     final AccessToken accessToken) {

		this(clientID, accessToken, null, 0);
	}


	/**
	 * Creates a new client registration access token response.
	 *
	 * @param clientID     The client ID. Must not be {@code null}.
	 * @param accessToken  The registration access token. Must not be
	 *                     {@code null}.
	 * @param clientSecret Optional client secret, {@code null} if none.
	 * @param expiresAt    Optional expiration time of the client secret,
	 *                     as number of seconds from 1970-01-01T0:0:0Z as 
	 *                     measured in UTC; zero if not specified.
	 */
	public ClientRegistrationAccessTokenResponse(final ClientID clientID,
		                                     final AccessToken accessToken,
		                                     final String clientSecret,
		                                     final long expiresAt) {

		super(clientID);

		this.accessToken = accessToken;

		this.clientSecret = clientSecret;

		this.expiresAt = expiresAt;
	}


	/**
	 * Gets the registration access token. Corresponds to the
	 * {@code registration_access_token} parameter.
	 *
	 * @return The registration access token.
	 */
	public AccessToken getRegistrationAccessToken() {

		return accessToken;
	}


	/**
	 * Gets the optional client secret. Corresponds to the 
	 * {@code client_secret} parameter.
	 *
	 * @return The client secret, {@code null} if none.
	 */
	public String getClientSecret() {

		return clientSecret;
	}


	/**
	 * Gets the optional expiration time of the client secret. Corresponds
	 * to the {@code expires_at} parameter.
	 *
	 * @return The expiration time of the client secret, as number of
	 *         seconds from 1970-01-01T0:0:0Z as measured in UTC; zero if
	 *         not specified.
	 */
	public long getClientSecretExpirationTime() {

		return expiresAt;
	}


	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");

		JSONObject json = new JSONObject();

		json.put("client_id", getClientID().getClaimValue());

		json.put("registration_access_token", accessToken.getValue());

		if (clientSecret != null)
			json.put("client_secret", clientSecret);

		if (expiresAt > 0)
			json.put("expires_at", expiresAt);
		
		httpResponse.setContent(json.toString());
	
		return httpResponse;
	}
}