package com.nimbusds.openid.connect.sdk;


import java.util.Date;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SuccessResponse;

import com.nimbusds.oauth2.sdk.auth.Secret;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.id.ClientID;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Connect client rotate secret success response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 *   "client_id"                 : "s6BhdRkqt3",
 *   "registration_access_token" : "aa3ff73233b04af1b56ab3f9c1f632a1",
 *   "client_secret"             : "08996de3fb9c499eaa35f93564633309",
 *   "expires_at"                : 2893276800
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-29)
 */
public class ClientRotateSecretSuccessResponse 
	extends ClientRotateSecretResponse
	implements SuccessResponse {


	/**
	 * The client identifier.
	 */
	private final ClientID clientID;


	/**
	 * The registration access token.
	 */
	private final AccessToken accessToken;


	/**
	 * The client secret.
	 */
	private final Secret clientSecret;


	/**
	 * Creates a new OpenID Connect client rotate secret success response.
	 *
	 * @param clientID    The client identifier. Must not be {@code null}.
	 * @param accessToken The registration access token. Must not be
	 *                    {@code null}.
	 */
	public ClientRotateSecretSuccessResponse(final ClientID clientID, 
		                                 final AccessToken accessToken) {

		this(clientID, accessToken, null);
	}


	/**
	 * Creates a new OpenID Connect client rotate secret success response.
	 *
	 * @param clientID     The client identifier. Must not be {@code null}.
	 * @param accessToken  The registration access token. Must not be
	 *                     {@code null}.
	 * @param clientSecret The client secret, with optional expiration 
	 *                     date, {@code null} if none.
	 */
	public ClientRotateSecretSuccessResponse(final ClientID clientID, 
		                                 final AccessToken accessToken,
		                                 final Secret clientSecret) {

		if (clientID == null)
			throw new IllegalArgumentException("The client identifier must not be null");

		this.clientID = clientID;


		if (accessToken == null)
			throw new IllegalArgumentException("The registration access token must not be null");

		this.accessToken = accessToken;


		this.clientSecret = clientSecret;
	}


	/**
	 * Gets the client identifier.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {

		return clientID;
	}


	/**
	 * Gets the registration access token.
	 *
	 * @return The access token.
	 */
	public AccessToken getAccessToken() {

		return accessToken;
	}


	/**
	 * Gets the client secret, with optional expiration date.
	 *
	 * @return The client secret, {@code null} if none.
	 */
	public Secret getClientSecret() {

		return clientSecret;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject jsonObject = new JSONObject();

		jsonObject.put("client_id", clientID.getValue());

		jsonObject.put("registration_access_token", accessToken.getValue());

		if (clientSecret != null) {

			jsonObject.put("client_secret", clientSecret.getValue());

			if (clientSecret.getExpirationDate() != null)
				jsonObject.put("expires_at", clientSecret.getExpirationDate().getTime());
			else
				jsonObject.put("expires_at", 0l);
		}

		return jsonObject;
	}


	/**
	 * Parses an OpenID Connect client rotate secret success response from 
	 * the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect client rotate secret success response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client rotate secret success 
	 *                        response.
	 */
	public static ClientRotateSecretSuccessResponse parse(final JSONObject jsonObject)
		throws ParseException {

		ClientID clientID = new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));

		AccessToken accessToken = new TypelessAccessToken(
			JSONObjectUtils.getString(jsonObject, "registration_access_token"));

		Secret clientSecret = ClientRegisterResponse.parseClientSecret(jsonObject);

		return new ClientRotateSecretSuccessResponse(clientID, accessToken, clientSecret);
	}


	/**
	 * Parses an OpenID Connect client rotate secret success response from 
	 * the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect client rotate secret success response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect client rotate secret success 
	 *                        response.
	 */
	public static ClientRotateSecretSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);

		httpResponse.ensureContentType(CommonContentTypes.APPLICATION_JSON);

		JSONObject jsonObject = httpResponse.getContentAsJSONObject();

		return parse(jsonObject);
	}
}