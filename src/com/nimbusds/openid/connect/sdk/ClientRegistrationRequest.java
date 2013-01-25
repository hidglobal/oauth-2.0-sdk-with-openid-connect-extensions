package com.nimbusds.openid.connect.sdk;


import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.OAuth2Request;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.token.AccessToken;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * The base abstract class for OpenID Connect client registration requests.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-25)
 */
public abstract class ClientRegistrationRequest implements OAuth2Request {


	/**
	 * The registration operation (required).
	 */
	private final ClientRegistrationOperation operation;


	/**
	 * OAuth 2.0 access token (conditionally required).
	 */
	private AccessToken accessToken = null;


	/**
	 * Creates a new OpenID Connect client registration request.
	 *
	 * @param operation The client registration operation. Must not be 
	 *                  {@code null}.
	 */
	protected ClientRegistrationRequest(final ClientRegistrationOperation operation) {

		if (operation == null)
			throw new IllegalArgumentException("The client registration operation must not be null");

		this.operation = operation;
	}


	/**
	 * Gets the client registration operation. Corresponds to the 
	 * {@code operation} parameter.
	 *
	 * @return The client registration operation.
	 */
	public ClientRegistrationOperation getOperation() {

		return operation;
	}


	/**
	 * Gets the OAuth 2.0 access token. Corresponds to the 
	 * {@code access_token} parameter.
	 *
	 * @return The OAuth 2.0 access token, {@code null} if none.
	 */
	public AccessToken getAccessToken() {

		return accessToken;
	}


	/**
	 * Sets the OAuth 2.0 access token. Corresponds to the
	 * {@code access_token} parameter.
	 *
	 * @param accessToken The OAuth 2.0 access token, {@code null} if none.
	 */
	public void setAccessToken(final AccessToken accessToken) {

		this.accessToken = accessToken;
	}


	/**
	 * Returns the parameters for this client registration request. The 
	 * OAuth 2.0 access token will be included.
	 *
	 * @return The parameters.
	 */
	public Map<String,String> toParameters() {

		return toParameters(true);
	}


	/**
	 * Returns the parameters for this client registration request.
	 *
	 * @param includeAccessToken If {@code true} the OAuth 2.0 access token 
	 *                           will be included, else not.
	 *
	 * @return The parameters.
	 */
	public Map<String,String> toParameters(final boolean includeAccessToken) {

		Map <String,String> params = new LinkedHashMap<String,String>();

		params.put("operation", getOperation().toString());

		if (includeAccessToken && getAccessToken() != null)
			params.put("access_token", getAccessToken().getValue());

		return params;
	}


	/**
	 * Returns the matching HTTP POST request. If an OAuth 2.0 access token
	 * is specified it will be inlined in the HTTP request body.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the OpenID Connect request message
	 *                            couldn't be serialised to an HTTP POST 
	 *                            request.
	 */
	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException {

		return toHTTPRequest(true);
	}


	/**
	 * Returns the matching HTTP POST request.
	 *
	 * @param inlineAccessToken If {@code true} and if an OAuth 2.0 access 
	 *                          token is specified, it will be inlined in 
	 *                          the HTTP request body, else it will be 
	 *                          included in the HTTP Authorization header.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the OpenID Connect request message
	 *                            couldn't be serialised to an HTTP POST 
	 *                            request.
	 */
	public HTTPRequest toHTTPRequest(final boolean inlineAccessToken)
		throws SerializeException {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);

		String requestBody = URLUtils.serializeParameters(toParameters(inlineAccessToken));

		httpRequest.setQuery(requestBody);

		if (! inlineAccessToken && getAccessToken() != null)
			httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());

		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		return httpRequest;
	}


	/**
	 * Parses a client registration request from the specified HTTP POST
	 * request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * POST /connect/register HTTP/1.1
	 * Content-Type: application/x-www-form-urlencoded
	 * Host: server.example.com
	 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...
 	 * 
	 * operation=client_register
	 * &amp;application_type=web
	 * &amp;redirect_uris=https://client.example.org/callback%20https://client.example.org/callback2
	 * &amp;client_name=My%20Example%20
	 * &amp;client_name%23ja-Jpan-JP=ワタシ用の例
	 * &amp;logo_url=https://client.example.org/logo.png
	 * &amp;subject_type=pairwise
	 * &amp;sector_identifier_url=https://othercompany.com/file_of_redirect_uris.json
	 * &amp;token_endpoint_auth_method=client_secret_basic
	 * &amp;jwk_url=https://client.example.org/my_rsa_public_key.jwk
	 * &amp;userinfo_encrypted_response_alg=RSA1_5
	 * &amp;userinfo_encrypted_response_enc=A128CBC+HS256
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client registration request.
	 */
	public static ClientRegistrationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		if (! httpRequest.getMethod().equals(HTTPRequest.Method.POST)) 
			throw new ParseException("Invalid client registration request, must be sent by HTTP POST",
				                 OAuth2Error.INVALID_REQUEST);

		if (httpRequest.getQuery() == null)
			throw new ParseException("Missing client registration parameters",
				                 OAuth2Error.INVALID_REQUEST);
		

		// Decode and parse operation parameter
		Map <String,String> params = URLUtils.parseParameters(httpRequest.getQuery());

		ClientRegistrationOperation operation = ClientRegistrationOperation.parse(params);

		ClientRegistrationRequest req = null;

		switch (operation) {

			case CLIENT_REGISTER:
				return ClientRegisterRequest.parse(httpRequest);

			case ROTATE_SECRET:
				return ClientRotateSecretRequest.parse(httpRequest);

			case CLIENT_UPDATE:
				return ClientUpdateRequest.parse(httpRequest);

			default:
				throw new ParseException("Invalid \"operation\" parameter", OIDCError.INVALID_OPERATION);
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
			                 OIDCError.INVALID_CONFIGURATION_PARAMETER);
	}
}