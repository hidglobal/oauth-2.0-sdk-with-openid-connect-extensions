package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * The base abstract class for OpenID Connect client update success and error
 * responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, sections 2.2.3 and
 *         2.3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-29)
 */
public abstract class ClientUpdateResponse implements ClientRegistrationResponse {


	/**
	 * Parses an OpenID Connect client update success or error response 
	 * from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect client update success or error 
	 *         response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect client update success or
	 *                        error response.
	 */
	public static ClientUpdateResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK)
			return ClientUpdateSuccessResponse.parse(httpResponse);
		else
			return ClientUpdateErrorResponse.parse(httpResponse);
	}
}