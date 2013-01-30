package com.nimbusds.openid.connect.sdk;


import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * OpenID Connect client rotate secret request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-30)
 */
public class ClientRotateSecretRequest extends ClientRegistrationRequest {


	/**
	 * Creates a new OpenID Connect client rotate secret request.
	 *
	 * @param accessToken The OAuth 2.0 access token. Must not be 
	 *                    {@code null}.
	 */
	public ClientRotateSecretRequest(final AccessToken accessToken) {

		super(ClientRegistrationOperation.ROTATE_SECRET);

		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");

		setAccessToken(accessToken);
	}


	/**
	 * Parses an OpenID Connect client rotate secret request from the 
	 * specified HTTP POST request.
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
			throw new ParseException("Invalid client registration request, must be sent by HTTP POST");

		if (httpRequest.getQuery() == null)
			throw new ParseException("Missing client registration parameters");
		

		// Decode and parse POST parameters
		Map <String,String> params = URLUtils.parseParameters(httpRequest.getQuery());
		
		
		// Mandatory params

		ClientRegistrationOperation operation = ClientRegistrationOperation.parse(params);


		if (operation != ClientRegistrationOperation.ROTATE_SECRET)
			throw new ParseException("Invalid \"operation\" parameter", 
					         OIDCError.INVALID_OPERATION);


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