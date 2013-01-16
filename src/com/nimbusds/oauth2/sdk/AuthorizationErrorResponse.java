package com.nimbusds.oauth2.sdk;


import java.io.UnsupportedEncodingException;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Authorisation error response. This class is immutable.
 *
 * <p>Standard authorisation errors:
 *
 * <ul>
 *     <li>{@link OAuth2Error#INVALID_REQUEST}
 *     <li>{@link OAuth2Error#UNAUTHORIZED_CLIENT}
 *     <li>{@link OAuth2Error#ACCESS_DENIED}
 *     <li>{@link OAuth2Error#UNSUPPORTED_RESPONSE_TYPE}
 *     <li>{@link OAuth2Error#INVALID_SCOPE}
 *     <li>{@link OAuth2Error#SERVER_ERROR}
 *     <li>{@link OAuth2Error#TEMPORARILY_UNAVAILABLE}
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
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.2.1 and 4.2.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-16)
 */
@Immutable
public class AuthorizationErrorResponse implements OAuth2ErrorResponse {


	/**
	 * The standard OAuth 2.0 errors for an Authorisation error response.
	 */
	private static Set<OAuth2Error> stdErrors = new HashSet<OAuth2Error>();
	
	
	static {
		stdErrors.add(OAuth2Error.INVALID_REQUEST);
		stdErrors.add(OAuth2Error.UNAUTHORIZED_CLIENT);
		stdErrors.add(OAuth2Error.ACCESS_DENIED);
		stdErrors.add(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
		stdErrors.add(OAuth2Error.INVALID_SCOPE);
		stdErrors.add(OAuth2Error.SERVER_ERROR);
		stdErrors.add(OAuth2Error.TEMPORARILY_UNAVAILABLE);
	}
	
	
	/**
	 * Gets the standard OAuth 2.0 errors for an Authorisation error 
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<OAuth2Error> getStandardErrors() {
	
		return Collections.unmodifiableSet(stdErrors);
	}
	
	
	/**
	 * The redirect URI.
	 */
	private final URL redirectURI;
	
	 
	/**
	 * The error.
	 */
	private final OAuth2Error error;
	
	
	/**
	 * The response type set, used to determine redirect URL composition. 
	 * If unknown {@code null}.
	 */
	private final ResponseTypeSet rts;
	
	
	/**
	 * The optional state parameter to be echoed back to the client.
	 */
	private final State state;
	
	
	/**
	 * Creates a new authorisation error response.
	 *
	 * @param redirectURI The redirect URI. Must not be {@code null}.
	 * @param error       The OAuth 2.0 error. Should match one of the 
	 *                    {@link #getStandardErrors standard errors} for an 
	 *                    authorisation error response. Must not be 
	 *                    {@code null}.
	 * @param rts         The response type set, used to determine the
	 *                    redirect URL composition. If unknown
	 *                    {@code null}.
	 * @param state       The state parameter to be echoed back to the 
	 *                    client, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the specified error is not legal
	 *                                  for an authorisation error 
	 *                                  response.
	 */
	public AuthorizationErrorResponse(final URL redirectURI,
	                                  final OAuth2Error error,
					  final ResponseTypeSet rts,
					  final State state) {
					  
		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
		
		this.redirectURI = redirectURI;
		
		if (error == null)
			throw new IllegalArgumentException("The error code must not be null");
			
		this.error = error;
		
		this.rts = rts;
		
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
	public OAuth2Error getError() {
	
		return error;
	}
	
	
	/**
	 * Gets the response type set.
	 *
	 * @return The response type set, {@code null} if not specified.
	 */
	public ResponseTypeSet getResponseTypeSet() {
	
		return rts;
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
	 * Returns the redirect URL with the appended error response 
	 * parameters.
	 *
	 * @return The redirect URL with the appended error response 
	 *         parameters.
	 *
	 * @throws SerializeException If the redirect URL couldn't be composed.
	 */
	public URL toURL()
		throws SerializeException {
		
		StringBuilder sb = new StringBuilder(redirectURI.toString());
		
		if (rts == null || rts.contains(ResponseType.TOKEN))
			sb.append("#");
		else
			sb.append("?");
		
		try {
			sb.append("error=");
			sb.append(URLEncoder.encode(error.getValue(), "utf-8"));

			if (error.getDescription() != null) {
				sb.append("&error_description=");
				sb.append(URLEncoder.encode(error.getDescription(), "utf-8"));
			}
			
			if (error.getURI() != null) {
				sb.append("&error_uri=");
				sb.append(URLEncoder.encode(error.getURI().toString(), "utf-8"));
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
	 * @throws ParseException If the redirect URL couldn't be parsed to an
	 *                        authorisation error response.
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

				
		// Parse the error
		if (StringUtils.isUndefined(params.get("error")))
			throw new ParseException("Missing error code");

		// Parse error code
		String errorCode = params.get("error");

		String errorDescription = params.get("error_description");

		String errorURIString = params.get("error_uri");

		URL errorURI = null;

		if (errorURIString != null) {
			
			try {
				errorURI = new URL(errorURIString);
				
			} catch (MalformedURLException e) {
		
				throw new ParseException("Invalid error URI: " + errorURIString, e);
			}
		}


		OAuth2Error error = new OAuth2Error(errorCode, errorDescription, errorURI);
		
		
		// State
		State state = State.parse(params.get("state"));
		
		return new AuthorizationErrorResponse(URLUtils.getBaseURL(url), error, null, state);
	}
	
	
	/**
	 * Parses an authorisation error response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        authorisation error response.
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
