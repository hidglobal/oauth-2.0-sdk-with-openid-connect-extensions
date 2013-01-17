package com.nimbusds.oauth2.sdk;


import java.net.URL;


/**
 * Authorisation endpoint response. This is the base abstract class for
 * authorisation success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-17)
 */
public abstract class AuthorizationResponse implements OAuth2Response {


	/**
	 * Parses an authorisation response.
	 *
	 * @param url The URL to parse. May be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation success or error response.
	 *
	 * @throws ParseException If no authorisation response parameters were
	 *                        found in the URL.
	 */
	public static AuthorizationResponse parse(final URL url)
		throws ParseException {

		return null;
	}
}