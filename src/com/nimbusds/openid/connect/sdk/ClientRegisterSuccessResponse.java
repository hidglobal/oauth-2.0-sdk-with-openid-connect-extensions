package com.nimbusds.openid.connect.sdk;


import java.util.Date;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SuccessResponse;

import com.nimbusds.oauth2.sdk.auth.Secret;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.rp.Client;


/**
 * OpenID Connect client register success response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 *   "client_id"                       : "s6BhdRkqt3",
 *   "registration_access_token"       : "2c5550da9d904293bf5edd0506544c46",
 *   "client_secret"                   : "cf136dc3c1fd9153029bb9c6cc9ecead",
 *   "expires_at"                      : 2893276800,
 *   "token_endpoint_auth_method"      : "client_secret_basic",
 *   "application_type"                : "web",
 *   "redirect_uris"                   : "https://client.example.org/callback
 *                                        https://client.example.org/callback2",
 *   "client_name"                     : "My Client",
 *   "client_name#ja-Jpan-JP"          : "ワタシ用の例",
 *   "logo_url"                        : "https://client.example.org/logo.png",
 *   "subject_type"                    : "pairwise",
 *   "sector_identifier_url"           : "https://othercompany.com/file_of_redirect_uris.json"
 *   "jwk_url"                         : "https://client.example.org/my_rsa_public_key.jwk",
 *   "userinfo_encrypted_response_alg" : "RSA1_5",
 *   "userinfo_encrypted_response_enc" : "A128CBC+HS256"
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
 * @version $version$ (2013-01-28)
 */
public class ClientRegisterSuccessResponse 
	extends ClientRegisterResponse
	implements SuccessResponse {


	/**
	 * The client details.
	 */
	private final Client client;


	/**
	 * The registration access token.
	 */
	private final AccessToken accessToken;


	/**
	 * The client secret.
	 */
	private final Secret clientSecret;


	/**
	 * Creates a new OpenID Connect client register success response.
	 *
	 * @param client       The client details. Must not be {@code null}.
	 * @param accessToken  The registration access token. Must not be
	 *                     {@code null}.
	 */
	public ClientRegisterSuccessResponse(final Client client, 
		                             final AccessToken accessToken) {

		this(client, accessToken, null);
	}


	/**
	 * Creates a new OpenID Connect client register success response.
	 *
	 * @param client       The client details. Must not be {@code null}.
	 * @param accessToken  The registration access token. Must not be
	 *                     {@code null}.
	 * @param clientSecret The client secret, with optional expiration 
	 *                     date, {@code null} if none.
	 */
	public ClientRegisterSuccessResponse(final Client client, 
		                             final AccessToken accessToken,
		                             final Secret clientSecret) {

		if (client == null)
			throw new IllegalArgumentException("The client details must not be null");

		this.client = client;


		if (accessToken == null)
			throw new IllegalArgumentException("The registration access token must not be null");

		this.accessToken = accessToken;


		this.clientSecret = clientSecret;
	}


	/**
	 * Gets the client details.
	 *
	 * @return The client details.
	 */
	public Client getClientDetails() {

		return client;
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


	public JSONObject toJSONObject() {

		JSONObject jsonObject = client.toJSONObject();

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
	 * Parses an OpenID Connect client register success response from the
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect client register success response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client register success 
	 *                        response.
	 */
	public static ClientRegisterSuccessResponse parse(final JSONObject jsonObject)
		throws ParseException {

		Client client = Client.parse(jsonObject);

		AccessToken accessToken = new TypelessAccessToken(
			JSONObjectUtils.getString(jsonObject, "registration_access_token"));

		Secret clientSecret = ClientRegisterResponse.parseClientSecret(jsonObject);
		
		return new ClientRegisterSuccessResponse(client, accessToken, clientSecret);
	}


	/**
	 * Parses an OpenID Connect client register success response from the
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect client register success response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect client register success 
	 *                        response.
	 */
	public static ClientRegisterSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);

		httpResponse.ensureContentType(CommonContentTypes.APPLICATION_JSON);

		JSONObject jsonObject = httpResponse.getContentAsJSONObject();

		return parse(jsonObject);
	}
}