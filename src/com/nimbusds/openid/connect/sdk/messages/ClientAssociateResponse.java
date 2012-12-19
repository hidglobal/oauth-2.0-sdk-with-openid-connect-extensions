package com.nimbusds.openid.connect.sdk.messages;


import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.ParseException;

import com.nimbusds.openid.connect.sdk.claims.ClientID;

import com.nimbusds.openid.connect.sdk.http.HTTPResponse;


/**
 * Client associate response. This class is immutable.
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
@Immutable
public final class ClientAssociateResponse extends ClientRegistrationAccessTokenResponse {


	/**
	 * Creates a new client associate response.
	 *
	 * @param clientID    The client ID. Must not be {@code null}.
	 * @param accessToken The registration access token. Must not be
	 *                    {@code null}.
	 */
	public ClientAssociateResponse(final ClientID clientID,
		                       final AccessToken accessToken) {

		super(clientID, accessToken);
	}


	/**
	 * Creates a new client associate response.
	 *
	 * @param clientID     The client ID. Must not be {@code null}.
	 * @param accessToken  The registration access token. Must not be
	 *                     {@code null}.
	 * @param clientSecret Optional client secret, {@code null} if none.
	 * @param expiresAt    Optional expiration time of the client secret,
	 *                     as number of seconds from 1970-01-01T0:0:0Z as 
	 *                     measured in UTC; zero if not specified.
	 */
	public ClientAssociateResponse(final ClientID clientID,
		                       final AccessToken accessToken,
		                       final String clientSecret,
		                       final long expiresAt) {

		super(clientID, accessToken, clientSecret, expiresAt);
	}


	/**
	 * Parses a client associate response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The client associate response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        valid client associate response.
	 */
	public static ClientAssociateResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		ClientRegistrationAccessTokenResponse response = 
			ClientRegistrationAccessTokenResponse.parse(httpResponse);

		return new ClientAssociateResponse(response.getClientID(),
			                           response.getRegistrationAccessToken(),
			                           response.getClientSecret(),
			                           response.getClientSecretExpirationTime());
	}
}