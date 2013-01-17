package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringEscapeUtils;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Bearer access token error response. Used to indicate that access to a
 * resource protected by a Bearer access token is denied.
 *
 * <p>Standard bearer access token errors:
 *
 * <ul>
 *     <li>{@link OAuth2Error#INVALID_REQUEST}
 *     <li>{@link OAuth2Error#INVALID_TOKEN}
 *     <li>{@link OAuth2Error#INSUFFICIENT_SCOPE}
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
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-17)
 */
@Immutable
public class BearerAccessTokenErrorResponse implements OAuth2ErrorResponse {


	/**
	 * The standard OAuth 2.0 errors for a Bearer access token error 
	 * response.
	 */
	private static final Set<OAuth2Error> stdErrors = new HashSet<OAuth2Error>();
	
	
	static {
		stdErrors.add(OAuth2Error.INVALID_REQUEST);
		stdErrors.add(OAuth2Error.INVALID_TOKEN);
		stdErrors.add(OAuth2Error.INSUFFICIENT_SCOPE);
	}
	
	
	/**
	 * Regex pattern for matching the realm parameter of a WWW-Authenticate 
	 * header.
	 */
	private static final Pattern realmPattern = Pattern.compile("realm=\"([^\"]+)");

	
	/**
	 * Regex pattern for matching the error parameter of a WWW-Authenticate 
	 * header.
	 */
	private static final Pattern errorPattern = Pattern.compile("error=\"([^\"]+)");


	/**
	 * Regex pattern for matching the error description parameter of a 
	 * WWW-Authenticate header.
	 */
	private static final Pattern errorDescriptionPattern = Pattern.compile("error_description=\"([^\"]+)\"");
	
	
	/**
	 * Regex pattern for matching the error URI parameter of a 
	 * WWW-Authenticate header.
	 */
	private static final Pattern errorURIPattern = Pattern.compile("error_uri=\"([^\"]+)\"");
	
	
	/**
	 * Gets the standard OAuth 2.0 errors for a Bearer access token error 
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<OAuth2Error> getStandardErrors() {
	
		return Collections.unmodifiableSet(stdErrors);
	}
	
	
	/**
	 * The authenticating realm, {@code null} if not specified.
	 */
	private final String realm;
	
	
	/**
	 * The error, {@code null} if the client didn't provide any 
	 * authentication information in the original request.
	 */
	private final OAuth2Error error;
	
	
	/**
	 * Creates a new Bearer access token error response.
	 *
	 * @param realm The bearer realm. May be {@code null}.
	 * @param error The OAuth 2.0 error. Should match one of the 
	 *              {@link #getStandardErrors standard errors} for a bearer 
	 *              access token error response. Should be {@code null} if 
	 *              the client didn't provide any authentication 
	 *              information in the original request.
	 */
	protected BearerAccessTokenErrorResponse(final String realm, 
		                                 final OAuth2Error error) {
	
		this.realm = realm;

		this.error = error;
	}
	
	
	/**
	 * Gets the authenticating realm.
	 *
	 * @return The authenticating realm, {@code null} if not specified.
	 */
	public String getRealm() {
	
		return realm;
	}
	

	@Override
	public OAuth2Error getError() {
	
		return error;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse httpResponse = null;
		
		// Set HTTP status code
		if (error == null)
			httpResponse = new HTTPResponse(HTTPResponse.SC_UNAUTHORIZED); // 401
			
		else if (error == OAuth2Error.INVALID_REQUEST)
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST); // 400
		
		else if (error == OAuth2Error.INVALID_TOKEN)
			httpResponse = new HTTPResponse(HTTPResponse.SC_UNAUTHORIZED); // 401
		
		else if (error == OAuth2Error.INSUFFICIENT_SCOPE)
			httpResponse = new HTTPResponse(HTTPResponse.SC_FORBIDDEN); // 403
		
		else
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST); // 400
		
		
		// Compose the WWW-Authenticate header
		
		StringBuilder sb = new StringBuilder("Bearer");
		
		int numParams = 0;
		
		if (realm != null) {
			sb.append(" realm=\"");
			sb.append(StringEscapeUtils.escapeJava(realm));
			sb.append('"');
			
			numParams++;
		}
		
		if (error != null) {
			
			if (numParams > 0)
				sb.append(',');
			
			sb.append(" error=\"");
			sb.append(StringEscapeUtils.escapeJava(error.getValue()));
			sb.append('"');
			numParams++;
			
			if (error.getDescription() != null) {

				if (numParams > 0)
					sb.append(',');

				sb.append(" error_description=\"");
				sb.append(StringEscapeUtils.escapeJava(error.getDescription()));
				sb.append('"');
				numParams++;
			}

			if (error.getURI() != null) {
		
				if (numParams > 0)
					sb.append(',');
				
				sb.append(" error_uri=\"");
				sb.append(StringEscapeUtils.escapeJava(error.getURI().toString()));
				sb.append('"');
				numParams++;
			}
		}
		
		
		httpResponse.setWWWAuthenticate(sb.toString());
		
		return httpResponse;
	}


	/**
	 * Parses a Bearer access token error response from the specified HTTP
	 * response WWW-Authenticate header.
	 *
	 * @param wwwAuth The WWW-Authenticate header value to parse. Must not 
	 *                be {@code null}.
	 *
	 * @throws ParseException If the WWW-Authenticate header value couldn't 
	 *                        be parsed to a Bearer access token error 
	 *                        response.
	 */
	public static BearerAccessTokenErrorResponse parse(final String wwwAuth)
		throws ParseException {

		// We must have a WWW-Authenticate header set to Bearer .*
		if (! wwwAuth.regionMatches(true, 0, "Bearer", 0, "Bearer".length()))
			throw new ParseException("WWW-Authenticate scheme must be OAuth 2.0 Bearer");
		
		Matcher m = null;
		
		// Parse optional realm
		m = realmPattern.matcher(wwwAuth);
		
		String realm = null;
		
		if (m.find())
			realm = m.group(1);
		
		
		// Parse optional error 
		OAuth2Error error = null;

		m = errorPattern.matcher(wwwAuth);

		
		if (m.find()) {

			String errorCode = m.group(1);

			// Parse optional error description
			m = errorDescriptionPattern.matcher(wwwAuth);

			String errorDescription = null;

			if (m.find())
				errorDescription = m.group(1);

			
			// Parse optional error URI
			m = errorURIPattern.matcher(wwwAuth);
			
			URL errorURI = null;
			
			if (m.find()) {
			
				try {
					errorURI = new URL(m.group(1));
					
				} catch (MalformedURLException e) {
				
					throw new ParseException("Invalid error URI: " + m.group(1), e);
				}
			}

			error = new OAuth2Error(errorCode, errorDescription, errorURI);
		}
			
		
		return new BearerAccessTokenErrorResponse(realm, error);
	}
	
	
	/**
	 * Parses a Bearer access token error response from the specified HTTP
	 * response.
	 *
	 * <p>Note: The HTTP status code is not checked for matching the error
	 * code semantics.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        Bearer access token error response.
	 */
	public static BearerAccessTokenErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		String wwwAuth = httpResponse.getWWWAuthenticate();
		
		if (wwwAuth == null)
			throw new ParseException("Missing HTTP WWW-Authenticate header");

		return parse(wwwAuth);
	}
}
