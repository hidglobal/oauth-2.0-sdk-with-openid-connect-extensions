package com.nimbusds.oauth2.sdk.http;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

import net.jcip.annotations.ThreadSafe;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * HTTP response with support for the parameters required to construct an 
 * {@link com.nimbusds.oauth2.sdk.Response OAuth 2.0 response message}.
 *
 * <p>Provided HTTP status code constants:
 *
 * <ul>
 *     <li>{@link #SC_OK HTTP 200 OK}
 *     <li>{@link #SC_CREATED HTTP 201 Created}
 *     <li>{@link #SC_FOUND HTTP 302 Redirect}
 *     <li>{@link #SC_BAD_REQUEST HTTP 400 Bad request}
 *     <li>{@link #SC_UNAUTHORIZED HTTP 401 Unauthorized}
 *     <li>{@link #SC_FORBIDDEN HTTP 403 Forbidden}
 *     <li>{@link #SC_SERVER_ERROR HTTP 500 Server error}
 * </ul>
 *
 * <p>Supported response headers:
 *
 * <ul>
 *     <li>Location
 *     <li>Content-Type
 *     <li>Cache-Control
 *     <li>Pragma
 *     <li>Www-Authenticate
 * </ul>
 */
@ThreadSafe
public class HTTPResponse extends HTTPMessage {

	
	/**
	 * HTTP status code (200) indicating the request succeeded.
	 */
	public static final int SC_OK = 200;


	/**
	 * HTTP status code (201) indicating the request succeeded with a new
	 * resource being created.
	 */
	public static final int SC_CREATED = 201;
	
	
	/**
	 * HTTP status code (302) indicating that the resource resides
	 * temporarily under a different URI (redirect).
	 */
	public static final int SC_FOUND = 302;
	
	
	/**
	 * HTTP status code (400) indicating a bad request.
	 */
	public static final int SC_BAD_REQUEST = 400;
	
	
	/**
	 * HTTP status code (401) indicating that the request requires HTTP 
	 * authentication.
	 */
	public static final int SC_UNAUTHORIZED = 401;
	
	
	/**
	 * HTTP status code (403) indicating that access to the resource was
	 * forbidden.
	 */
	public static final int SC_FORBIDDEN = 403;


	/**
	 * HTTP status code (500) indicating an internal server error.
	 */
	public static final int SC_SERVER_ERROR = 500;


	/**
	 * HTTP status code (503) indicating the server is unavailable.
	 */
	public static final int SC_SERVICE_UNAVAILABLE = 503;


	/**
	 * The HTTP status code.
	 */
	private final int statusCode;
	
	
	/**
	 * The raw response content.
	 */
	private String content = null;
	
	
	/**
	 * Creates a new minimal HTTP response with the specified status code.
	 *
	 * @param statusCode The HTTP status code.
	 */
	public HTTPResponse(final int statusCode) {
	
		this.statusCode = statusCode;
	}
	
	
	/**
	 * Gets the HTTP status code.
	 *
	 * @return The HTTP status code.
	 */
	public int getStatusCode() {
	
		return statusCode;
	}


	/**
	 * Returns {@code true} if the HTTP status code indicates success
	 * (2xx).
	 *
	 * @return {@code true} if the HTTP status code indicates success, else
	 *         {@code false}.
	 */
	public boolean indicatesSuccess() {

		return statusCode >= 200 && statusCode < 300;
	}
	
	
	/**
	 * Ensures this HTTP response has the specified status code.
	 *
	 * @param expectedStatusCode The expected status code(s).
	 *
	 * @throws ParseException If the status code of this HTTP response 
	 *                        doesn't match the expected.
	 */ 
	public void ensureStatusCode(final int ... expectedStatusCode)
		throws ParseException {

		for (int c: expectedStatusCode) {

			if (this.statusCode == c)
				return;
		}

		throw new ParseException("Unexpected HTTP status code " + 
			this.statusCode + 
			", must be " +  
			Arrays.toString(expectedStatusCode));
	}


	/**
	 * Ensures this HTTP response does not have a {@link #SC_OK 200 OK} 
	 * status code.
	 *
	 * @throws ParseException If the status code of this HTTP response is
	 *                        200 OK.
	 */
	public void ensureStatusCodeNotOK()
		throws ParseException {

		if (statusCode == SC_OK)
			throw new ParseException("Unexpected HTTP status code, must not be 200 (OK)");
	}
	
	
	/**
	 * Gets the {@code Location} header value (for redirects).
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public URI getLocation() {

		String value = getHeader("Location");

		if (value == null) {
			return null;
		}

		try {
			return new URI(value);

		} catch (URISyntaxException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the {@code Location} header value (for redirects).
	 *
	 * @param location The header value, {@code null} if not specified.
	 */
	public void setLocation(final URI location) {
	
		setHeader("Location", location != null ? location.toString() : null);
	}
	
	
	/**
	 * Gets the {@code Cache-Control} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getCacheControl() {
	
		return getHeader("Cache-Control");
	}


	/**
	 * Sets the {@code Cache-Control} header value.
	 *
	 * @param cacheControl The header value, {@code null} if not specified.
	 */
	public void setCacheControl(final String cacheControl) {
	
		setHeader("Cache-Control", cacheControl);
	}
	
	
	/**
	 * Gets the {@code Pragma} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getPragma() {
	
		return getHeader("Pragma");
	}
	
	
	/**
	 * Sets the {@code Pragma} header value.
	 *
	 * @param pragma The header value, {@code null} if not specified.
	 */
	public void setPragma(final String pragma) {
	
		setHeader("Pragma", pragma);
	}
	
	
	/**
	 * Gets the {@code WWW-Authenticate} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getWWWAuthenticate() {
	
		return getHeader("WWW-Authenticate");
	}
	
	
	/**
	 * Sets the {@code WWW-Authenticate} header value.
	 *
	 * @param wwwAuthenticate The header value, {@code null} if not 
	 *                        specified.
	 */
	public void setWWWAuthenticate(final String wwwAuthenticate) {
	
		setHeader("WWW-Authenticate", wwwAuthenticate);
	}
	
	
	/**
	 * Ensures this HTTP response has a specified content body.
	 *
	 * @throws ParseException If the content body is missing or empty.
	 */
	private void ensureContent()
		throws ParseException {
		
		if (content == null || content.isEmpty())
			throw new ParseException("Missing or empty HTTP response body");
	}
	
	
	/**
	 * Gets the raw response content.
	 *
	 * @return The raw response content, {@code null} if none.
	 */
	public String getContent() {
	
		return content;
	}
	
	
	/**
	 * Gets the response content as a JSON object.
	 *
	 * @return The response content as a JSON object.
	 *
	 * @throws ParseException If the Content-Type header isn't 
	 *                        {@code application/json}, the response
	 *                        content is {@code null}, empty or couldn't be
	 *                        parsed to a valid JSON object.
	 */
	public JSONObject getContentAsJSONObject()
		throws ParseException {
		
		ensureContentType(CommonContentTypes.APPLICATION_JSON);
		
		ensureContent();
		
		return JSONObjectUtils.parse(content);
	}


	/**
	 * Gets the response content as a JSON array.
	 *
	 * @return The response content as a JSON array.
	 *
	 * @throws ParseException If the Content-Type header isn't
	 *                        {@code application/json}, the response
	 *                        content is {@code null}, empty or couldn't be
	 *                        parsed to a valid JSON array.
	 */
	public JSONArray getContentAsJSONArray()
		throws ParseException {

		ensureContentType(CommonContentTypes.APPLICATION_JSON);

		ensureContent();

		return JSONArrayUtils.parse(content);
	}
	
	
	/**
	 * Gets the response content as a JSON Web Token (JWT).
	 *
	 * @return The response content as a JSON Web Token (JWT).
	 *
	 * @throws ParseException If the Content-Type header isn't
	 *                        {@code application/jwt}, the response content 
	 *                        is {@code null}, empty or couldn't be parsed
	 *                        to a valid JSON Web Token (JWT).
	 */
	public JWT getContentAsJWT()
		throws ParseException {
		
		ensureContentType(CommonContentTypes.APPLICATION_JWT);
		
		ensureContent();
		
		try {
			return JWTParser.parse(content);
			
		} catch (java.text.ParseException e) {
		
			throw new ParseException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Sets the raw response content.
	 *
	 * @param content The raw response content, {@code null} if none.
	 */
	public void setContent(final String content) {
	
		this.content = content;
	}
}
