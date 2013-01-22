package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.BearerAccessTokenErrorResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * UserInfo error response. This class is immutable.
 *
 * <p>Standard errors:
 *
 * <ul>
 *     <li>OAuth 2.0 Bearer Token errors:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_REQUEST}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_TOKEN}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INSUFFICIENT_SCOPE}
 *          </ul>
 *     <li>OpenID Connect specific errors:
 *         <ul>
 *             <li>{@link OIDCError#INVALID_SCHEMA}
 *         </ul>
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: Bearer realm="example.com",
 *                   error="invalid_token",
 *                   error_description="The access token expired"
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.3.3.
 *     <li>OpenID Connect Standard 1.0, section 4.3.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-22)
 */
@Immutable
public final class UserInfoErrorResponse extends BearerAccessTokenErrorResponse {


	/**
	 * Gets the standard errors for a UserInfo error response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<OAuth2Error> getStandardErrors() {
		
		Set<OAuth2Error> bearerErrors = BearerAccessTokenErrorResponse.getStandardErrors();
		
		Set<OAuth2Error> stdErrors = new HashSet<OAuth2Error>(bearerErrors);
		stdErrors.add(OIDCError.INVALID_SCHEMA);

		return Collections.unmodifiableSet(stdErrors);
	}
	

	/**
	 * Creates a new UserInfo error response.
	 *
	 * @param realm The bearer realm. May be {@code null}.
	 * @param error The OAuth 2.0 error. Should match one of the 
	 *              {@link #getStandardErrors standard errors} for a 
	 *              UserInfo error response. Should be {@code null} if 
	 *              the client didn't provide any authentication 
	 *              information in the original request.
	 */
	public UserInfoErrorResponse(final String realm, 
	                             final OAuth2Error error) {
				    
		super(realm, error);
	}


	/**
	 * Parses a UserInfo error response from the specified HTTP response
	 * {@code WWW-Authenticate} header.
	 *
	 * @param wwwAuth The {@code WWW-Authenticate} header value to parse. 
	 *                Must not be {@code null}.
	 *
	 * @throws ParseException If the {@code WWW-Authenticate} header value 
	 *                        couldn't be parsed to a UserInfo error 
	 *                        response.
	 */
	public static UserInfoErrorResponse parse(final String wwwAuth)
		throws ParseException {

		BearerAccessTokenErrorResponse ber = BearerAccessTokenErrorResponse.parse(wwwAuth);

		return new UserInfoErrorResponse(ber.getRealm(), ber.getError());
	}
	
	
	/**
	 * Parses a UserInfo error response from the specified HTTP response.
	 *
	 * <p>Note: The HTTP status code is not checked for matching the error
	 * code semantics.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        UserInfo error response.
	 */
	public static UserInfoErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		String wwwAuth = httpResponse.getWWWAuthenticate();
		
		if (wwwAuth == null)
			throw new ParseException("Missing HTTP WWW-Authenticate header");

		return parse(wwwAuth);
	}
}
