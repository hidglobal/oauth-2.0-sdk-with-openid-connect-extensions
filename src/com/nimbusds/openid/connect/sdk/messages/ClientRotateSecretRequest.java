package com.nimbusds.openid.connect.sdk.messages;


import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.CommonContentTypes;
import com.nimbusds.openid.connect.sdk.http.HTTPRequest;

import com.nimbusds.openid.connect.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.util.URLUtils;


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
 * @version $version$ (2012-12-18)
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
			httpRequest.setAuthorization("Bearer " + getAccessToken().getValue());

		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		return httpRequest;
	}


	/**
	 * Parses a client rotate secret request from the specified HTTP POST
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The parsed client rotate secret request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        valid client rotate secret request.
	 */
	public static ClientRotateSecretRequest parse(final HTTPRequest httpRequest)
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


		if (! type.equals(ClientRegistrationType.ROTATE_SECRET))
			throw new ParseException("Invalid \"type\" parameter", ErrorCode.INVALID_TYPE);


		// Parse the access token

		AccessToken accessToken = null;

		if (httpRequest.getAuthorization() != null) {

			// Access token in header

			String authzHeader = httpRequest.getAuthorization();

			if (! authzHeader.startsWith("Bearer "))
				throw new ParseException("OAuth 2.0 Bearer Token authorization required",
					                 ErrorCode.INVALID_REQUEST);

			accessToken = new AccessToken(authzHeader.substring("Bearer".length()));
		}
		else if (StringUtils.isDefined(params.get("access_token"))) {

			// Access token inlined

			accessToken = new AccessToken(params.get("access_token"));
		}

		return new ClientRotateSecretRequest(accessToken);
	}
}