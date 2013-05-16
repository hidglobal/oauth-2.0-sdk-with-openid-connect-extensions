package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * The base abstract for OpenID Connect client registration responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, sections 3.2 and 
 *         3.3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public abstract class OIDCClientRegistrationResponse implements Response {


	/**
	 * Parses an OpenID Connect client registration response from the 
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The OpenID Connect client registration response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect client registration response.
	 */
	public static OIDCClientRegistrationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK)
			return OIDCClientDetailsResponse.parse(httpResponse);
		else
			return OIDCClientRegistrationErrorResponse.parse(httpResponse);
	}
}