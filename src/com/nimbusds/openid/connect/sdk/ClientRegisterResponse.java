package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * The base abstract class for OpenID Connect client register success and error
 * responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, sections 2.2.1 and
 *         2.3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-29)
 */
public abstract class ClientRegisterResponse extends ClientRegistrationResponse {


	/**
	 * Parses an OpenID Connect client register success or error response 
	 * from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect client register success or error 
	 *         response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect client register success or
	 *                        error response.
	 */
	public static ClientRegisterResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK)
			return ClientRegisterSuccessResponse.parse(httpResponse);
		else
			return ClientRegisterErrorResponse.parse(httpResponse);
	}
}