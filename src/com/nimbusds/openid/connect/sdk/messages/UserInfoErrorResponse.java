package com.nimbusds.openid.connect.sdk.messages;


import java.net.URL;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.openid.connect.sdk.ParseException;

import com.nimbusds.openid.connect.sdk.http.HTTPResponse;


/**
 * UserInfo error response. This class is immutable.
 *
 * <p>Legal error codes:
 *
 * <ul>
 *     <li>OAuth 2.0 errors:
 *         <ul>
 *             <li>{@link ErrorCode#INVALID_REQUEST}
 *             <li>{@link ErrorCode#INVALID_TOKEN}
 *             <li>{@link ErrorCode#INSUFFICIENT_SCOPE}
 *          </ul>
 *     <li>OpenID Connect specific error:
 *         <ul>
 *             <li>{@link ErrorCode#INVALID_SCHEMA}
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
 *     <li>The OAuth 2.0 Authorization Framework: Bearer Token Usage
 *         (draft-ietf-oauth-v2-bearer-23), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-22)
 */
public final class UserInfoErrorResponse extends OAuthBearerTokenErrorResponse {


	/**
	 * Gets the legal error codes for a UserInfo error response.
	 *
	 * @return The legal error codes, as a read-only set.
	 */
	public static Set<ErrorCode> getLegalErrorCodes() {
	
		Set<ErrorCode> bearerErrorCodes = OAuthBearerTokenErrorResponse.getStandardErrorCodes();
		
		Set<ErrorCode> codes = new HashSet<ErrorCode>(bearerErrorCodes);
		codes.add(ErrorCode.INVALID_SCHEMA);
		
		return Collections.unmodifiableSet(codes);
	}
	
	
	/**
	 * Gets the standard error codes for a UserInfo error response.
	 *
	 * @see #getLegalErrorCodes
	 *
	 * @return The standard error codes, as a read-only set.
	 */
	public static Set<ErrorCode> getStandardErrorCodes() {
	
		return getLegalErrorCodes();
	}
	

	/**
	 * Creates a new UserInfo error response.
	 *
	 * @param realm     The bearer realm. May be {@code null}.
	 * @param errorCode The error code. Must match one of the legal error 
	 *                  codes for a UserInfo error response. It may be 
	 *                  {@code null} if the client didn't provide any 
	 *                  authentication information in the original request.
	 * @param errorURI  Optional URI of a web page that includes information
	 *                  about the error, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the specified error code is not
	 *                                  legal for a UserInfo error response.
	 */
	public UserInfoErrorResponse(final String realm, 
	                             final ErrorCode errorCode,
				     final URL errorURI) {
				    
		super(realm, errorCode, errorURI);
		
		if (errorCode != null && ! getLegalErrorCodes().contains(errorCode))
			throw new IllegalArgumentException("Illegal UserInfo response error code: " + errorCode.getCode());
	}
	
	
	/**
	 * Parses a UserInfo error response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response cannot be parsed to a 
	 *                        valid UserInfo error response.
	 */
	public static UserInfoErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		OAuthBearerTokenErrorResponse r = OAuthBearerTokenErrorResponse.parse(httpResponse);
		
		if (r.getErrorCode() != null && ! getLegalErrorCodes().contains(r.getErrorCode()))
			throw new ParseException("Illegal UserInfo response error code: " + r.getErrorCode().getCode());
		
		return new UserInfoErrorResponse(r.getRealm(), r.getErrorCode(), r.getErrorURI());
	}
}
