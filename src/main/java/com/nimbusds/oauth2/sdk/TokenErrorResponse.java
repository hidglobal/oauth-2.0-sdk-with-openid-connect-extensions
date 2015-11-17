package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OAuth 2.0 Token error response.
 *
 * <p>Standard token errors:
 *
 * <ul>
 *     <li>{@link OAuth2Error#INVALID_REQUEST}
 *     <li>{@link OAuth2Error#INVALID_CLIENT}
 *     <li>{@link OAuth2Error#INVALID_GRANT}
 *     <li>{@link OAuth2Error#UNAUTHORIZED_CLIENT}
 *     <li>{@link OAuth2Error#UNSUPPORTED_GRANT_TYPE}
 *     <li>{@link OAuth2Error#INVALID_SCOPE}
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
 */
@Immutable
public class TokenErrorResponse extends TokenResponse implements ErrorResponse {


	/**
	 * The standard OAuth 2.0 errors for an Access Token error response.
	 */
	private static final Set<ErrorObject> STANDARD_ERRORS;
	
	
	static {
		Set<ErrorObject> errors = new HashSet<>();
		errors.add(OAuth2Error.INVALID_REQUEST);
		errors.add(OAuth2Error.INVALID_CLIENT);
		errors.add(OAuth2Error.INVALID_GRANT);
		errors.add(OAuth2Error.UNAUTHORIZED_CLIENT);
		errors.add(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		errors.add(OAuth2Error.INVALID_SCOPE);
		STANDARD_ERRORS = Collections.unmodifiableSet(errors);
	}
	
	
	/**
	 * Gets the standard OAuth 2.0 errors for an Access Token error 
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {
	
		return STANDARD_ERRORS;
	}
	
	
	/**
	 * The error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new OAuth 2.0 Access Token error response. No OAuth 2.0
	 * error is specified.
	 */
	protected TokenErrorResponse() {

		error = null;
	}
	
	
	/**
	 * Creates a new OAuth 2.0 Access Token error response.
	 *
	 * @param error The error. Should match one of the 
	 *              {@link #getStandardErrors standard errors} for a token 
	 *              error response. Must not be {@code null}.
	 */
	public TokenErrorResponse(final ErrorObject error) {
	
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
	
	
	/**
	 * Returns the JSON object for this token error response.
	 *
	 * @return The JSON object for this token error response.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();

		// No error?
		if (error == null)
			return o;

		o.put("error", error.getCode());

		if (error.getDescription() != null)
			o.put("error_description", error.getDescription());
		
		if (error.getURI() != null)
			o.put("error_uri", error.getURI().toString());
		
		return o;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {

		int statusCode = (error != null && error.getHTTPStatusCode() > 0) ?
			error.getHTTPStatusCode() : HTTPResponse.SC_BAD_REQUEST;

		HTTPResponse httpResponse = new HTTPResponse(statusCode);

		if (error == null)
			return httpResponse;
		
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		
		httpResponse.setContent(toJSONObject().toString());
		
		return httpResponse;
	}


	/**
	 * Parses an OAuth 2.0 Token Error response from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Its status code must not
	 *                   be 200 (OK). Must not be {@code null}.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an 
	 *                        OAuth 2.0 Token Error response.
	 */
	public static TokenErrorResponse parse(final JSONObject jsonObject)
		throws ParseException {

		// No error code?
		if (! jsonObject.containsKey("error"))
			return new TokenErrorResponse();
		
		ErrorObject error;
		
		try {
			// Parse code
			String code = JSONObjectUtils.getString(jsonObject, "error");

			// Parse description
			String description = null;

			if (jsonObject.containsKey("error_description"))
				description = JSONObjectUtils.getString(jsonObject, "error_description");

			// Parse URI
			URI uri = null;

			if (jsonObject.containsKey("error_uri"))
				uri = new URI(JSONObjectUtils.getString(jsonObject, "error_uri"));


			error = new ErrorObject(code, description, HTTPResponse.SC_BAD_REQUEST, uri);
			
		} catch (ParseException e) {
		
			throw new ParseException("Missing or invalid token error response parameter: " + e.getMessage(), e);
			
		} catch (URISyntaxException e) {
		
			throw new ParseException("Invalid error URI: " + e.getMessage(), e);
		}
		
		return new TokenErrorResponse(error);
	}
	
	
	/**
	 * Parses an OAuth 2.0 Token Error response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response to parse. Its status code must
	 *                     not be 200 (OK). Must not be {@code null}.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OAuth 2.0 Token Error response.
	 */
	public static TokenErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCodeNotOK();
		return new TokenErrorResponse(ErrorObject.parse(httpResponse));
	}
}
