package com.nimbusds.openid.connect.sdk.messages;


import java.util.Map;

import com.nimbusds.openid.connect.sdk.ParseException;

import com.nimbusds.openid.connect.sdk.http.HTTPRequest;

import com.nimbusds.openid.connect.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.util.URLUtils;


/**
 * The base abstract class for client registration requests.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-18)
 */
public abstract class ClientRegistrationRequest implements Request {


	/**
	 * The registration type (always required).
	 */
	private ClientRegistrationType type;


	/**
	 * OAuth 2.0 Bearer access token (conditionally optional).
	 */
	private AccessToken accessToken = null;


	/**
	 * Creates a new client registration request.
	 *
	 * @param type The client registration type. Must not be {@code null}.
	 */
	protected ClientRegistrationRequest(final ClientRegistrationType type) {

		if (type == null)
			throw new IllegalArgumentException("The client registration type must not be null");

		this.type = type;
	}


	/**
	 * Gets the client registration type. Corresponds to the {@code type}
	 * parameter.
	 *
	 * @return The client registration type.
	 */
	public ClientRegistrationType getType() {

		return type;
	}


	/**
	 * Gets the OAuth 2.0 Bearer access token. Corresponds to the
	 * {@code access_token} parameter.
	 *
	 * @return The OAuth 2.0 Bearer access token, {@code null} if none.
	 */
	public AccessToken getAccessToken() {

		return accessToken;
	}


	/**
	 * Sets the OAuth 2.0 Bearer access token. Corresponds to the
	 * {@code access_token} parameter.
	 *
	 * @param accessToken The OAuth 2.0 Bearer access token, {@code null} 
	 *                    if none.
	 */
	public void setAccessToken(final AccessToken accessToken) {

		this.accessToken = accessToken;
	}


	/**
	 * Parses a client registration request from the specified HTTP POST
	 * request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * POST /connect/register HTTP/1.1
	 * Accept: application/x-www-form-urlencoded
	 * Host: server.example.com
	 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ... fQ.8Gj_-sj ... _X
	 * 
	 * type=client_associate
	 * &application_type=web
	 * &redirect_uris=https://client.example.org/callback
	 *     %20https://client.example.org/callback2
	 * &application_name=My%20Example%20
	 * &application_name%23ja-Hani-JP=
	 * &logo_url=https://client.example.org/logo.png
	 * &user_id_type=pairwise
	 * &sector_identifier_url=
	 *     https://othercompany.com/file_of_redirect_uris_for_our_sites.js
	 * &token_endpoint_auth_type=client_secret_basic
	 * &jwk_url=https://client.example.org/my_rsa_public_key.jwk
	 * &userinfo_encrypted_response_alg=RSA1_5
	 * &userinfo_encrypted_response_enc=A128CBC+HS256
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The parsed client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        valid client registration request.
	 */
	public static ClientRegistrationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		if (! httpRequest.getMethod().equals(HTTPRequest.Method.POST)) 
			throw new ParseException("Invalid client registration request, must be sent by HTTP POST",
				                 ErrorCode.INVALID_REQUEST);

		if (httpRequest.getQuery() == null)
			throw new ParseException("Missing client registration parameters",
				                 ErrorCode.INVALID_REQUEST);
		

		// Decode and parse type parameter
		Map <String,String> params = URLUtils.parseParameters(httpRequest.getQuery());

		ClientRegistrationType type = null;

		try {
			type = parseEnum("type", ClientRegistrationType.class, params);

		} catch (ParseException e) {

			throw new ParseException("Invalid \"type\" parameter", ErrorCode.INVALID_TYPE);
		}


		if (type == null)
			throw new ParseException("Missing \"type\" parameter", ErrorCode.INVALID_TYPE);


		ClientRegistrationRequest req = null;

		switch (type) {

			case CLIENT_ASSOCIATE:
				return ClientAssociateRequest.parse(httpRequest);

			case ROTATE_SECRET:
				return ClientRotateSecretRequest.parse(httpRequest);

			case CLIENT_UPDATE:
				return ClientUpdateRequest.parse(httpRequest);

			default:
				throw new ParseException("Invalid \"type\" parameter", ErrorCode.INVALID_TYPE);
		}
	}


	/**
	 * Parses an enumerated configuration parameter.
	 *
	 * @param name       The parameter name. The corresponding parameter 
	 *                   value must match (case ignore) an enumeration
	 *                   constant or be undefined ({@code null}). The
	 *                   parameter name itself must not be {@code null}.
	 * @param enumClass  The enumeration class. Must not be {@code null}.
	 * @param params     The parameter map. Must not be {@code null}.
	 *
	 * @return The matching enumeration constant, {@code null} if the
	 *         parameter is not specified.
	 *
	 * @throws ParseException On a invalid enumeration value.
	 */
	protected static <T extends Enum<T>> T parseEnum(final String name, 
		                                         final Class<T> enumClass, 
		                                         final Map<String,String> params)
		throws ParseException {

		String value = params.get(name);

		if (StringUtils.isUndefined(value))
			return null;

		for (T en: enumClass.getEnumConstants()) {
			       
			if (en.toString().equalsIgnoreCase(value))
				return en;
		}

		throw new ParseException("Invalid \"" + name + "\" parameter",
			                 ErrorCode.INVALID_CONFIGURATION_PARAMETER);
	}
}