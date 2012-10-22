package com.nimbusds.openid.connect.messages;


import java.io.UnsupportedEncodingException;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.HTTPResponse;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Authorisation error response. This class is immutable.
 *
 * <p>Legal error codes:
 *
 * <ul>
 *     <li>OAuth 2.0 errors:
 *         <ul>
 *             <li>{@link ErrorCode#INVALID_REQUEST}
 *             <li>{@link ErrorCode#UNAUTHORIZED_CLIENT}
 *             <li>{@link ErrorCode#ACCESS_DENIED}
 *             <li>{@link ErrorCode#UNSUPPORTED_RESPONSE_TYPE}
 *             <li>{@link ErrorCode#INVALID_SCOPE}
 *             <li>{@link ErrorCode#SERVER_ERROR}
 *             <li>{@link ErrorCode#TEMPORARILY_UNAVAILABLE}
 *             <li>{@link ErrorCode#INVALID_REDIRECT_URI}
 *         </ul>
 *     <li>OpenID Connect specific errors:
 *         <ul>
 *             <li>{@link ErrorCode#INTERACTION_REQUIRED}
 *             <li>{@link ErrorCode#LOGIN_REQUIRED}
 *             <li>{@link ErrorCode#SESSION_SELECTION_REQUIRED}
 *             <li>{@link ErrorCode#CONSENT_REQUIRED}
 *             <li>{@link ErrorCode#INVALID_REQUEST_URI}
 *             <li>{@link ErrorCode#INVALID_OPENID_REQUEST_OBJECT}
 *         </ul>
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.com/cb?
 * error=invalid_request
 * &error_description=the%20request%20is%20not%20valid%20or%20malformed
 * &state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.4.
 *     <li>OpenID Connection Standard 1.0, section 2.3.5.2.
 *     <li>OAuth 2.0 (RFC 6749), section 4.1.2.1 and 4.2.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-21)
 */
public final class AuthorizationErrorResponse implements ErrorResponse {


	/**
	 * The legal error codes for an authorisation error response.
	 */
	private static Set<ErrorCode> legalErrorCodes = new HashSet<ErrorCode>();
	
	
	static {
		// OAuth 2.0 errors
		legalErrorCodes.add(ErrorCode.INVALID_REQUEST);
		legalErrorCodes.add(ErrorCode.UNAUTHORIZED_CLIENT);
		legalErrorCodes.add(ErrorCode.ACCESS_DENIED);
		legalErrorCodes.add(ErrorCode.UNSUPPORTED_RESPONSE_TYPE);
		legalErrorCodes.add(ErrorCode.INVALID_SCOPE);
		legalErrorCodes.add(ErrorCode.SERVER_ERROR);
		legalErrorCodes.add(ErrorCode.TEMPORARILY_UNAVAILABLE);
		
		// OpenID Connect specific errors
		legalErrorCodes.add(ErrorCode.INVALID_REDIRECT_URI);
		legalErrorCodes.add(ErrorCode.INTERACTION_REQUIRED);
		legalErrorCodes.add(ErrorCode.LOGIN_REQUIRED);
		legalErrorCodes.add(ErrorCode.SESSION_SELECTION_REQUIRED);
		legalErrorCodes.add(ErrorCode.CONSENT_REQUIRED);
		legalErrorCodes.add(ErrorCode.INVALID_REQUEST_URI);
		legalErrorCodes.add(ErrorCode.INVALID_OPENID_REQUEST_OBJECT);
	}
	
	
	/**
	 * Gets the legal error codes for an authorisation error response.
	 *
	 * @return The legal error codes, as a read-only set.
	 */
	public static Set<ErrorCode> getLegalErrorCodes() {
	
		return Collections.unmodifiableSet(legalErrorCodes);
	}
	
	
	/**
	 * The redirect URI.
	 */
	private final URL redirectURI;
	
	 
	/**
	 * The error code.
	 */
	private final ErrorCode errorCode;
	
	
	/**
	 * The URL of a web page that includes additional information about the
	 * error.
	 */
	private final URL errorURI;
	
	
	/**
	 * The response type set, used to determine redirect URL composition. If
	 * unknown {@code null}.
	 */
	private final ResponseTypeSet responseTypeSet;
	
	
	/**
	 * The state parameter to be echoed back to the client.
	 */
	private final State state;
	
	
	/**
	 * Creates a new authorisation error response.
	 *
	 * @param redirectURI     The redirect URI. Must not be {@code null}.
	 * @param errorCode       The error code. Must match one of the 
	 *                        {@link #getLegalErrorCodes legal error codes}
	 *                        for an authorisation error response and must 
	 *                        not be {@code null}.
	 * @param errorURI        Optional URI of a web page that includes 
	 *                        information about the error, {@code null} if 
	 *                        not specified.
	 * @param responseTypeSet The response type set, used to determine 
	 *                        redirect URL composition. If unknown
	 *                        {@code null}.
	 * @param state           The state parameter to be echoed back to the 
	 *                        client, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the specified error code is not
	 *                                  legal for an authorisation error 
	 *                                  response.
	 */
	public AuthorizationErrorResponse(final URL redirectURI,
	                                  final ErrorCode errorCode,
	                                  final URL errorURI,
					  final ResponseTypeSet responseTypeSet,
					  final State state) {
					  
		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
		
		this.redirectURI = redirectURI;
		
		if (errorCode == null)
			throw new IllegalArgumentException("The error code must not be null");
		
		if (! legalErrorCodes.contains(errorCode))
			throw new IllegalArgumentException("Illegal error code");
			
		this.errorCode = errorCode;
		
		this.errorURI = errorURI;
		
		this.responseTypeSet = responseTypeSet;
		
		this.state = state;
	}
	
	
	/**
	 * Gets the base redirect URI.
	 *
	 * @return The base redirect URI (without the appended error response 
	 *         parameters).
	 */
	public URL getRedirectURI() {
	
		return redirectURI;
	}
	

	@Override
	public ErrorCode getErrorCode() {
	
		return errorCode;
	}
	
	
	@Override
	public URL getErrorURI() {
	
		return errorURI;
	}
	
	
	/**
	 * Gets the response type set.
	 *
	 * @return The response type set.
	 */
	public ResponseTypeSet getResponseTypeSet() {
	
		return responseTypeSet;
	}
	
	
	/**
	 * Gets the state parameter to be echoed back to the client.
	 *
	 * @return The state, {@code null} if not specified.
	 */
	public State getState() {
	
		return state;
	}
	
	
	/**
	 * Returns the redirect URL with the appended error response parameters.
	 *
	 * @return The redirect URL with the appended error response parameters.
	 *
	 * @throws SerializeException If the redirect URL couldn't couldn't be
	 *                            produced.
	 */
	public URL toURL()
		throws SerializeException {
		
		StringBuilder sb = new StringBuilder(redirectURI.toString());
		
		if (responseTypeSet == null ||
		    responseTypeSet.contains(ResponseType.TOKEN) ||
		    responseTypeSet.contains(ResponseType.ID_TOKEN))
			sb.append("#");
		else
			sb.append("?");
		
		try {
			sb.append("error=");
			sb.append(URLEncoder.encode(errorCode.getCode(), "utf-8"));

			sb.append("&error_description=");
			sb.append(URLEncoder.encode(errorCode.getDescription(), "utf-8"));

			if (errorURI != null) {
				sb.append("&error_uri=");
				sb.append(URLEncoder.encode(errorURI.toString(), "utf-8"));
			}

			if (state != null) {
				sb.append("&state=");
				sb.append(URLEncoder.encode(state.toString(), "utf-8"));
			}
			
		} catch (UnsupportedEncodingException e) {
		
			throw new SerializeException("Couldn't serialize redirect URL: " + e.getMessage(), e);
		}
		
		try {
			return new URL(sb.toString());
			
		} catch (MalformedURLException e) {
		
			throw new SerializeException("Couldn't serialize redirect URL: " + e.getMessage(), e);
		}
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse response = new HTTPResponse(HTTPResponse.SC_FOUND);
		
		response.setLocation(toURL());
		
		return response;
	}
	
	
	/**
	 * Parses an authorisation error response.
	 *
	 * @param url The redirect URL to parse. Must not be {@code null}.
	 *
	 * @throws ParseException If the redirect URL cannot be parsed to a 
	 *                        valid authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final URL url)
		throws ParseException {
		
		Map<String,String> params = null;
		
		if (url.getRef() != null)
			params = URLUtils.parseParameters(url.getRef());
		else if (url.getQuery() != null)
			params = URLUtils.parseParameters(url.getQuery());
		else
			throw new ParseException("Missing URL reference or query string");
		
		// Parse the error code
		String errorCodeString = params.remove("error");
		ErrorCode errorCode = null;
		
		try {
			errorCode = ErrorCode.valueOf(errorCodeString.toUpperCase());
			
		} catch (NullPointerException e) {
		
			throw new ParseException("Missing error code");
		
		} catch (IllegalArgumentException e) {
		
			throw new ParseException("Invalid error code: " + errorCodeString);
		}
		
		// Ignore description
		params.remove("error_description");
		
		// Error page
		String urlString = params.remove("error_uri");
		URL errorURI = null;
		
		if (urlString != null) {
			
			try {
				errorURI = new URL(urlString);
				
			} catch (MalformedURLException e) {
		
				throw new ParseException("Invalid error URI: " + urlString, e);
			}
		}
		
		// State
		String stateString = params.remove("state");
		State state = null;
		
		if (stateString != null)
			state = new State(stateString);
		
		// More params in URL?
		if (params.size() > 0)
			throw new ParseException("Unexpected parameter(s) in URL reference or query string");
		
		if (! getLegalErrorCodes().contains(errorCode))
			throw new ParseException("Illegal authorization response error code: " + errorCode.getCode());
		
		return new AuthorizationErrorResponse(URLUtils.getBaseURL(url), errorCode, errorURI, null, state);
	}
	
	
	/**
	 * Parses an authorisation error response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response cannot be parsed to a 
	 *                        valid authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() != HTTPResponse.SC_FOUND)
			throw new ParseException("Unexpected HTTP status code, must be 302 (Found): " + httpResponse.getStatusCode());
		
		URL location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirect URL / HTTP Location header");
		
		return parse(location);
	}
}
