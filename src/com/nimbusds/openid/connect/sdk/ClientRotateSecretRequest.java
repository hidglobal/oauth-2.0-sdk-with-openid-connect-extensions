package com.nimbusds.openid.connect.sdk;


import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Client rotate secret request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-22)
 */
public class ClientRotateSecretRequest extends ClientRegistrationRequest {


	/**
	 * Creates a new client rotate secret request.
	 *
	 * @param accessToken The OAuth 2.0 Bearer access token, {@code null} 
	 *                    if none.
	 */
	public ClientRotateSecretRequest(final AccessToken accessToken) {

		super(ClientRegistrationType.ROTATE_SECRET);

		setAccessToken(accessToken);
	}


	/**
	 * Returns the matching HTTP POST request. If an access token is
	 * specified it will be inlined in the HTTP request body.
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
	 * @param inlineAccessToken If {@code true} the access token will be
	 *                          inlined in the HTTP request body, else it
	 *                          will be included as an OAuth 2.0 Bearer
	 *                          Token in the HTTP Authorization header.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the OpenID Connect request message
	 *                            couldn't be serialised to an HTTP POST 
	 *                            request.
	 */
	public HTTPRequest toHTTPRequest(final boolean inlineAccessToken)
		throws SerializeException {
	
		Map <String,String> params = new LinkedHashMap<String,String>();

		params.put("type", getType().toString());


		if (inlineAccessToken && getAccessToken() != null)
			params.put("access_token", getAccessToken().getValue());


		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);

		String requestBody = URLUtils.serializeParameters(params);

		httpRequest.setQuery(requestBody);

		if (! inlineAccessToken && getAccessToken() != null)
			httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());

		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		return httpRequest;
	}


	/**
	 * Parses a client rotate secret request from the specified HTTP POST
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client rotate secret request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client rotate secret request.
	 */
	public static ClientRotateSecretRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		if (! httpRequest.getMethod().equals(HTTPRequest.Method.POST)) 
			throw new ParseException("Invalid client registration request, must be sent by HTTP POST",
				                 OAuth2Error.INVALID_REQUEST);

		if (httpRequest.getQuery() == null)
			throw new ParseException("Missing client registration parameters",
				                 OAuth2Error.INVALID_REQUEST);
		

		// Decode and parse type parameter
		Map <String,String> params = URLUtils.parseParameters(httpRequest.getQuery());

		ClientRegistrationType type = null;

		try {
			type = parseEnum("type", ClientRegistrationType.class, params);

		} catch (ParseException e) {

			throw new ParseException("Invalid \"type\" parameter", OIDCError.INVALID_TYPE);
		}


		if (type == null)
			throw new ParseException("Missing \"type\" parameter", OIDCError.INVALID_TYPE);


		if (! type.equals(ClientRegistrationType.ROTATE_SECRET))
			throw new ParseException("Invalid \"type\" parameter", OIDCError.INVALID_TYPE);


		// Parse the access token

		AccessToken accessToken = null;

		if (StringUtils.isDefined(httpRequest.getAuthorization())) {

			// Access token in header
			accessToken = AccessToken.parse(httpRequest.getAuthorization());
		}
		else if (StringUtils.isDefined(params.get("access_token"))) {

			// Access token inlined
			accessToken = new TypelessAccessToken(params.get("access_token"));
		}

		return new ClientRotateSecretRequest(accessToken);
	}
}