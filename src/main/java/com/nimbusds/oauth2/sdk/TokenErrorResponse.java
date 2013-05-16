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
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class TokenErrorResponse 
	extends TokenResponse
	implements ErrorResponse {


	/**
	 * The standard OAuth 2.0 errors for an Access Token error response.
	 */
	private static final Set<ErrorObject> stdErrors = new HashSet<ErrorObject>();
	
	
	static {
		stdErrors.add(OAuth2Error.INVALID_REQUEST);
		stdErrors.add(OAuth2Error.INVALID_CLIENT);
		stdErrors.add(OAuth2Error.INVALID_GRANT);
		stdErrors.add(OAuth2Error.UNAUTHORIZED_CLIENT);
		stdErrors.add(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		stdErrors.add(OAuth2Error.INVALID_SCOPE);
	}
	
	
	/**
	 * Gets the standard OAuth 2.0 errors for an Access Token error 
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
		
		// HTTP status 400
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
		
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
		
		ErrorObject error = null;
		
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


			error = new ErrorObject(code, description, HTTPResponse.SC_BAD_REQUEST, uri);
			
		} catch (ParseException e) {
		
			throw new ParseException("Missing or invalid token error response parameter: " + e.getMessage(), e);
			
		} catch (MalformedURLException e) {
		
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

		JSONObject jsonObject = httpResponse.getContentAsJSONObject();

		return parse(jsonObject);
	}
}
