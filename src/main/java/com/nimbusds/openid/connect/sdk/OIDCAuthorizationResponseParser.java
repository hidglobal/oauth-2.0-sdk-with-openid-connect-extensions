package com.nimbusds.openid.connect.sdk;


import java.net.URL;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Parser of OpenID Connect authorisation response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, sections 2.1.2 and 2.1.3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCAuthorizationResponseParser { 


	/**
	 * Parses an OpenID Connect authorisation success or error response
	 * from the specified redirect URI and parameters.
	 *
	 * @param redirectURI The base redirect URI. Must not be {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authorisation success or error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authorisation success or error
	 *                        response.
	 */
	public static OIDCAuthorizationResponse parse(final URL redirectURI, 
		                                      final Map<String,String> params)
		throws ParseException {


		if (params.containsKey("error"))
			return OIDCAuthorizationErrorResponse.parse(redirectURI, params);
		else
			return OIDCAuthorizationSuccessResponse.parse(redirectURI, params);
	}


	/**
	 * Parses an OpenID Connect authorisation success or error response
	 * from the specified URI.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authorisation success or error response.
	 *
	 * @throws ParseException If the redirect URI couldn't be parsed to an
	 *                        OpenID Connect authorisation success or error
	 *                        response.
	 */
	public static OIDCAuthorizationResponse parse(final URL uri)
		throws ParseException {

		String paramString = null;
		
		if (uri.getQuery() != null)
			paramString = uri.getQuery();
				
		else if (uri.getRef() != null)
			paramString = uri.getRef();
		
		else
			throw new ParseException("Missing authorization response parameters");
		
		Map<String,String> params = URLUtils.parseParameters(paramString);

		if (params == null)
			throw new ParseException("Missing or invalid authorization response parameters");

		return parse(URLUtils.getBaseURL(uri), params);
	}


	/**
	 * Parses an OpenID Connect authorisation success or error response 
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
	 * @return The OpenID Connect authorisation success or error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect authorisation success or error
	 *                        response.
	 */
	public static OIDCAuthorizationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		if (httpResponse.getStatusCode() != HTTPResponse.SC_FOUND)
			throw new ParseException("Unexpected HTTP status code, must be 302 (Found): " + 
			                         httpResponse.getStatusCode());
		
		URL location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirect URL / HTTP Location header");
		
		return parse(location);
	}


	/**
	 * Prevents public instantiation.
	 */
	private OIDCAuthorizationResponseParser() { }
}
