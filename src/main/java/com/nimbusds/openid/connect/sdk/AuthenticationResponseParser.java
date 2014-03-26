package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Parser of OpenID Connect authentication response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.2.5. and 3.1.2.6.
 * </ul>
 */
public class AuthenticationResponseParser {


	/**
	 * Parses an OpenID Connect authentication success or error response
	 * from the specified redirection URI and parameters.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication success or
	 *                        error response.
	 */
	public static AuthenticationResponse parse(final URI redirectURI,
						   final Map<String,String> params)
		throws ParseException {


		if (params.containsKey("error"))
			return AuthenticationErrorResponse.parse(redirectURI, params);
		else
			return AuthenticationSuccessResponse.parse(redirectURI, params);
	}


	/**
	 * Parses an OpenID Connect authentication success or error response
	 * from the specified URI.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authentication
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the redirection URI couldn't be parsed to
	 *                        an OpenID Connect authentication success or
	 *                        error response.
	 */
	public static AuthenticationResponse parse(final URI uri)
		throws ParseException {

		String paramString;
		
		if (uri.getQuery() != null)
			paramString = uri.getQuery();
				
		else if (uri.getFragment() != null)
			paramString = uri.getFragment();
		
		else
			throw new ParseException("Missing authorization response parameters");
		
		Map<String,String> params = URLUtils.parseParameters(paramString);

		if (params == null)
			throw new ParseException("Missing or invalid authorization response parameters");

		return parse(URIUtils.getBaseURI(uri), params);
	}


	/**
	 * Parses an OpenID Connect authentication success or error response
	 * from the specified HTTP response.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect authentication success or
	 *                        error response.
	 */
	public static AuthenticationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		if (httpResponse.getStatusCode() != HTTPResponse.SC_FOUND)
			throw new ParseException("Unexpected HTTP status code, must be 302 (Found): " + 
			                         httpResponse.getStatusCode());
		
		URL location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirection URI / HTTP Location header");

		try {
			return parse(location.toURI());

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private AuthenticationResponseParser() { }
}
