package com.nimbusds.oauth2.sdk.client;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * The base abstract for client registration responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-18), section 3.2.
 * </ul>
 */
public abstract class ClientRegistrationResponse implements Response {


	/**
	 * Parses a client registration response from the specified HTTP 
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The client registration response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        client registration response.
	 */
	public static ClientRegistrationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() == HTTPResponse.SC_CREATED ||
		    httpResponse.getStatusCode() == HTTPResponse.SC_OK) {

			return ClientInformationResponse.parse(httpResponse);

		} else {

			return ClientRegistrationErrorResponse.parse(httpResponse);
		}
	}
}