package com.nimbusds.openid.connect.messages;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.mail.internet.ContentType;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPResponse;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * OAuth 2.0 Access Token error response.
 *
 * <p>Legal error codes:
 *
 * <ul>
 *     <li>OAuth 2.0 errors:
 *         <ul>
 *             <li>{@link ErrorCode#INVALID_REQUEST}
 *             <li>{@link ErrorCode#INVALID_CLIENT}
 *             <li>{@link ErrorCode#INVALID_GRANT}
 *             <li>{@link ErrorCode#UNAUTHORIZED_CLIENT}
 *             <li>{@link ErrorCode#UNSUPPORTED_GRANT_TYPE}
 *             <li>{@link ErrorCode#INVALID_SCOPE}
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
 * <p>See http://tools.ietf.org/html/draft-ietf-oauth-v2-26#section-5.2
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-03)
 */
public class TokenErrorResponse implements ErrorResponse {


	/**
	 * The legal error codes for an OAuth 2.0 Access Token error response.
	 */
	private static Set<ErrorCode> legalErrorCodes = new HashSet<ErrorCode>();
	
	
	static {
		// OAuth 2.0 errors
		legalErrorCodes.add(ErrorCode.INVALID_REQUEST);
		legalErrorCodes.add(ErrorCode.INVALID_CLIENT);
		legalErrorCodes.add(ErrorCode.INVALID_GRANT);
		legalErrorCodes.add(ErrorCode.UNAUTHORIZED_CLIENT);
		legalErrorCodes.add(ErrorCode.UNSUPPORTED_GRANT_TYPE);
		legalErrorCodes.add(ErrorCode.INVALID_SCOPE);
	}
	
	
	/**
	 * Gets the legal error codes for an OAuth 2.0 Access Token error 
	 * response.
	 *
	 * @return The legal error codes, as a read-only set.
	 */
	public static Set<ErrorCode> getLegalErrorCodes() {
	
		return Collections.unmodifiableSet(legalErrorCodes);
	}
	
	
	/**
	 * The error code.
	 */
	private ErrorCode errorCode;
	
	
	/**
	 * The URL of a web page that includes additional information about the
	 * error.
	 */
	private URL errorURI = null;
	
	
	/**
	 * Creates a new OAuth 2.0 Access Token error response.
	 *
	 * @param errorCode   The error code. Must match one of the 
	 *                    {@link #getLegalErrorCodes legal error codes} for
	 *                    an authorisation error response and must not be 
	 *                    {@code null}.
	 * @param errorURI    Optional URI of a web page that includes 
	 *                    information about the error, {@code null} if not
	 *                    specified.
	 *
	 * @throws IllegalArgumentException If the specified error code is not
	 *                                  legal for an authorisation error 
	 *                                  response.
	 */
	public TokenErrorResponse(final ErrorCode errorCode, final URL errorURI) {
	
		if (errorCode == null)
			throw new NullPointerException("The error code must not be null");
		
		if (! legalErrorCodes.contains(errorCode))
			throw new IllegalArgumentException("Illegal error code");
			
		this.errorCode = errorCode;
		
		this.errorURI = errorURI;
	}
	

	/**
	 * @inheritDoc
	 */
	public ErrorCode getErrorCode() {
	
		return errorCode;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public URL getErrorURI() {
	
		return errorURI;
	}
	
	
	/**
	 * Returns the JSON object for this token error response.
	 *
	 * @return The JSON object for this token error response.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
		o.put("error", errorCode.getCode());
		o.put("error_description", errorCode.getDescription());
		
		if (errorURI != null)
			o.put("error_uri", errorURI.toString());
		
		return o;
	}
	
	
	/**
	 * @inheritDoc
	 */
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
		
		if (httpResponse.getStatusCode() != HTTPResponse.SC_BAD_REQUEST)
		       throw new ParseException("Unexpected HTTP status code, must be 400 (Bad request): " + httpResponse.getStatusCode());

		// Cache-Control and Pragma headers are ignored
		
		ContentType contentType = httpResponse.getContentType();
		
		if (contentType == null)
			throw new ParseException("Missing HTTP Content-Type header");
		
		if (! contentType.match(CommonContentTypes.APPLICATION_JSON))
			throw new ParseException("Expected HTTP Content-Type \"" + CommonContentTypes.APPLICATION_JSON + "\"");
		
		String content = httpResponse.getContent();
		
		if (content == null)
			throw new ParseException("Missing HTTP content");
		
		JSONObject jsonObject = null;
		
		try {
			jsonObject = JSONObjectUtils.parseJSONObject(content);
		
		} catch (ParseException e) {
		
			throw new ParseException("Invalid JSON object: " + e.getMessage(), e);
		}
		
		String errorCodeString = null;
		ErrorCode errorCode = null;
		URL errorURI = null;
		
		try {
			errorCodeString = JSONObjectUtils.getString(jsonObject, "error");
			errorCode = ErrorCode.valueOf(errorCodeString.toUpperCase());
			
			if (jsonObject.containsKey("error_uri"))
				errorURI = new URL(JSONObjectUtils.getString(jsonObject, "error_uri"));
			
		} catch (ParseException e) {
		
			throw new ParseException("Missing or invalid token error response parameter: " + e.getMessage(), e);
			
		} catch (IllegalArgumentException e) {
		
			throw new ParseException("Invalid error code: " + errorCodeString, e);
		
		} catch (MalformedURLException e) {
		
			throw new ParseException("Invalid error URI: " + e.getMessage(), e);
		}
		
		
		if (! getLegalErrorCodes().contains(errorCode))
			throw new ParseException("Illegal token response error code: " + errorCode.getCode());
		
		return new TokenErrorResponse(errorCode, errorURI);
	}
}
