package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Authorisation error response.
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
 * &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
 * &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.2.1 and 4.2.2.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 * </ul>
 */
@Immutable
public class AuthorizationErrorResponse
	extends AuthorizationResponse
	implements ErrorResponse {


	/**
	 * The standard OAuth 2.0 errors for an Authorisation error response.
	 */
	private static final Set<ErrorObject> stdErrors = new HashSet<>();
	
	
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
	public static Set<ErrorObject> getStandardErrors() {
	
		return Collections.unmodifiableSet(stdErrors);
	}
	
	
	/**
	 * The error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new authorisation error response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param error       The error. Should match one of the
	 *                    {@link #getStandardErrors standard errors} for an
	 *                    authorisation error response. Must not be
	 *                    {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 * @param rm          The implied response mode, {@code null} if
	 *                    unknown.
	 */
	public AuthorizationErrorResponse(final URI redirectURI,
					  final ErrorObject error,
					  final State state,
					  final ResponseMode rm) {

		super(redirectURI, state, rm);

		if (error == null)
			throw new IllegalArgumentException("The error must not be null");

		this.error = error;
	}


	@Override
	public boolean indicatesSuccess() {

		return false;
	}
	

	@Override
	public ErrorObject getErrorObject() {
	
		return error;
	}


	@Override
	public ResponseMode impliedResponseMode() {

		// Return "query" if not known, assumed the most frequent case
		return getResponseMode() != null ? getResponseMode() : ResponseMode.QUERY;
	}


	@Override
	public Map<String,String> toParameters() {

		Map<String,String> params = new HashMap<>();

		params.put("error", error.getCode());

		if (error.getDescription() != null)
			params.put("error_description", error.getDescription());

		if (error.getURI() != null)
			params.put("error_uri", error.getURI().toString());

		if (getState() != null)
			params.put("state", getState().getValue());

		return params;
	}


	/**
	 * Parses an authorisation error response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The authorisation error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final URI redirectURI,
		                                       final Map<String,String> params)
		throws ParseException {

		// Parse the error
		if (StringUtils.isBlank(params.get("error")))
			throw new ParseException("Missing error code");

		// Parse error code
		String errorCode = params.get("error");

		String errorDescription = params.get("error_description");

		String errorURIString = params.get("error_uri");

		URI errorURI = null;

		if (errorURIString != null) {
			
			try {
				errorURI = new URI(errorURIString);
				
			} catch (URISyntaxException e) {
		
				throw new ParseException("Invalid error URI: " + errorURIString, e);
			}
		}

		ErrorObject error = new ErrorObject(errorCode, errorDescription, HTTPResponse.SC_FOUND, errorURI);
		
		
		// State
		State state = State.parse(params.get("state"));
		
		return new AuthorizationErrorResponse(redirectURI, error, state, null);
	}
	
	
	/**
	 * Parses an authorisation error response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("https:///?error=invalid_request");
	 * </pre>
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?
	 * error=invalid_request
	 * &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation error response.
	 *
	 * @throws ParseException If the URI couldn't be parsed to an
	 *                        authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final URI uri)
		throws ParseException {
		
		Map<String,String> params;

		if (uri.getRawFragment() != null) {

			params = URLUtils.parseParameters(uri.getRawFragment());

		} else if (uri.getRawQuery() != null) {

			params = URLUtils.parseParameters(uri.getRawQuery());

		} else {

			throw new ParseException("Missing URI fragment or query string");
		}

		
		return parse(URIUtils.getBaseURI(uri), params);
	}
	
	
	/**
	 * Parses an authorisation error response from the specified initial
	 * HTTP 302 redirect response generated at the authorisation endpoint.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?error=invalid_request&amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @see #parse(HTTPRequest)
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The authorisation error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		URI location = httpResponse.getLocation();

		if (location == null) {
			throw new ParseException("Missing redirection URL / HTTP Location header");
		}

		return parse(location);
	}


	/**
	 * Parses an authorisation error response from the specified HTTP
	 * request at the client redirection (callback) URI. Applies to
	 * {@code query}, {@code fragment} and {@code form_post} response
	 * modes.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?error=invalid_request&amp;state=af0ifjsldkj HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #parse(HTTPResponse)
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null}.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final HTTPRequest httpRequest)
		throws ParseException {

		final URI baseURI;

		try {
			baseURI = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {
			throw new ParseException(e.getMessage(), e);
		}

		if (httpRequest.getQuery() != null) {
			// For query string and form_post response mode
			return parse(baseURI, URLUtils.parseParameters(httpRequest.getQuery()));
		} else if (httpRequest.getFragment() != null) {
			// For fragment response mode (never available in actual HTTP request from browser)
			return parse(baseURI, URLUtils.parseParameters(httpRequest.getFragment()));
		} else {
			throw new ParseException("Missing URI fragment, query string or post body");
		}
	}
}
