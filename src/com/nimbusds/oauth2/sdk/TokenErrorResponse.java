package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OAuth 2.0 Token error response. This class is immutable.
 *
 * <p>Legal error codes:
 *
 * <ul>
 *     <li>OAuth 2.0 errors:
 *         <ul>
 *             <li>{@link OAuth2Error#INVALID_REQUEST}
 *             <li>{@link OAuth2Error#INVALID_CLIENT}
 *             <li>{@link OAuth2Error#INVALID_GRANT}
 *             <li>{@link OAuth2Error#UNAUTHORIZED_CLIENT}
 *             <li>{@link OAuth2Error#UNSUPPORTED_GRANT_TYPE}
 *             <li>{@link OAuth2Error#INVALID_SCOPE}
 *         </ul>
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 * 
 * {
 *  "error": "invalid_request"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 5.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
@Immutable
public final class TokenErrorResponse implements ErrorResponse {


	/**
	 * The legal errors for an OAuth 2.0 Access Token error response.
	 */
	private static final Set<OAuth2Error> legalErrors = new HashSet<OAuth2Error>();
	
	
	static {
		legalErrors.add(OAuth2Error.INVALID_REQUEST);
		legalErrors.add(OAuth2Error.INVALID_CLIENT);
		legalErrors.add(OAuth2Error.INVALID_GRANT);
		legalErrors.add(OAuth2Error.UNAUTHORIZED_CLIENT);
		legalErrors.add(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		legalErrors.add(OAuth2Error.INVALID_SCOPE);
	}
	
	
	/**
	 * Gets the legal OAuth 2.0 errors for an Access Token error response.
	 *
	 * @return The legal errors, as a read-only set.
	 */
	public static Set<OAuth2Error> getLegalErrors() {
	
		return Collections.unmodifiableSet(legalErrors);
	}
	
	
	/**
	 * The error.
	 */
	private final OAuth2Error error;
	
	
	/**
	 * Creates a new OAuth 2.0 Access Token error response.
	 *
	 * @param error The OAuth 2.0 error. Must match one of the 
	 *              {@link #getLegalErrors legal errors} for a token error
	 *              response and must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the specified error code is not
	 *                                  legal for a token error response.
	 */
	public TokenErrorResponse(final OAuth2Error error) {
	
		if (error == null)
			throw new IllegalArgumentException("The OAuth 2.0 error must not be null");
		
		if (! legalErrors.contains(error))
			throw new IllegalArgumentException("Illegal OAuth 2.0 error");
			
		this.error = error;
	}
	

	@Override
	public OAuth2Error getError() {
	
		return error;
	}
	
	
	/**
	 * Returns the JSON object for this token error response.
	 *
	 * @return The JSON object for this token error response.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();

		o.put("error", error.getValue());

		if (error.getDescription() != null)
			o.put("error_description", error.getDescription());
		
		if (error.getURI() != null)
			o.put("error_uri", error.getURI().toString());
		
		return o;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
		
		// HTTP status 400
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
		
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		
		httpResponse.setContent(toJSONObject().toString());
		
		return httpResponse;
	}
	
	
	/**
	 * Parses an OAuth 2.0 Token Error response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response cannot be parsed to a 
	 *                        valid OAuth 2.0 Token Error response.
	 */
	public static TokenErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_BAD_REQUEST);

		// Cache-Control and Pragma headers are ignored
		
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		
		OAuth2Error error = null;
		
		try {
			// Parse code
			String code = JSONObjectUtils.getString(jsonObject, "error");

			// Parse description
			String description = null;

			if (jsonObject.containsKey("error_description"))
				description = JSONObjectUtils.getString(jsonObject, "error_description");

			// Parse URI
			URL uri = null;

			if (jsonObject.containsKey("error_uri"))
				uri = new URL(JSONObjectUtils.getString(jsonObject, "error_uri"));


			error = new OAuth2Error(code, description, uri);
			
		} catch (ParseException e) {
		
			throw new ParseException("Missing or invalid token error response parameter: " + e.getMessage(), e);
			
		} catch (MalformedURLException e) {
		
			throw new ParseException("Invalid error URI: " + e.getMessage(), e);
		}
		
		
		if (! getLegalErrors().contains(error))
			throw new ParseException("Illegal token response error code: " + error.getValue());
		
		return new TokenErrorResponse(error);
	}
}
