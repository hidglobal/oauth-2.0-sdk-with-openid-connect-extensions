package com.nimbusds.oauth2.sdk.http;


import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;

import javax.servlet.http.HttpServletResponse;

import net.jcip.annotations.ThreadSafe;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * HTTP response with support for the parameters required to construct an 
 * {@link com.nimbusds.oauth2.sdk.Response OAuth 2.0 response message}. This
 * class is thread-safe.
 *
 * <p>Provided HTTP status code constants:
 *
 * <ul>
 *     <li>{@link #SC_OK HTTP 200 OK}
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
 *
 * @author Vladimir Dzhuvinov
 */
@ThreadSafe
public final class HTTPResponse extends HTTPMessage {

	
	/**
	 * HTTP status code (200) indicating the request succeeded.
	 */
	public static final int SC_OK = 200;
	
	
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
	 * Specifies a {@code Location} header value (for redirects).
	 */
	private URL location = null;
	
	
	/**
	 * Specifies a {@code Cache-Control} header value.
	 */
	private String cacheControl = null;
	
	
	/**
	 * Specifies a {@code Pragma} header value.
	 */
	private String pragma = null;
	
	
	/**
	 * Specifies a {@code WWW-Authenticate} header value.
	 */
	private String wwwAuthenticate = null;
	
	
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
	 * Ensures this HTTP response has the specified {@link #getStatusCode
	 * status code}.
	 *
	 * @param statusCode The expected status code.
	 *
	 * @throws ParseException If the status code of this HTTP response 
	 *                        doesn't match the expected.
	 */ 
	public void ensureStatusCode(final int statusCode)
		throws ParseException {
	
		if (this.statusCode != statusCode)
			throw new ParseException("Unexpected HTTP status code, must be " +  statusCode);
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
	public URL getLocation() {
	
		return location;
	}
	
	
	/**
	 * Sets the {@code Location} header value (for redirects).
	 *
	 * @param location The header value, {@code null} if not specified.
	 */
	public void setLocation(final URL location) {
	
		this.location = location;
	}
	
	
	/**
	 * Gets the {@code Cache-Control} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getCacheControl() {
	
		return cacheControl;
	}


	/**
	 * Sets the {@code Cache-Control} header value.
	 *
	 * @param cacheControl The header value, {@code null} if not specified.
	 */
	public void setCacheControl(final String cacheControl) {
	
		this.cacheControl = cacheControl;
	}
	
	
	/**
	 * Gets the {@code Pragma} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getPragma() {
	
		return pragma;
	}
	
	
	/**
	 * Sets the {@code Pragma} header value.
	 *
	 * @param pragma The header value, {@code null} if not specified.
	 */
	public void setPragma(final String pragma) {
	
		this.pragma = pragma;
	}
	
	
	/**
	 * Gets the {@code WWW-Authenticate} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getWWWAuthenticate() {
	
		return wwwAuthenticate;
	}
	
	
	/**
	 * Sets the {@code WWW-Authenticate} header value.
	 *
	 * @param wwwAuthenticate The header value, {@code null} if not 
	 *                        specified.
	 */
	public void setWWWAuthenticate(final String wwwAuthenticate) {
	
		this.wwwAuthenticate = wwwAuthenticate;
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
	 *                        {@code application/json}, the response content
	 *                        is {@code null}, empty or couldn't be parsed
	 *                        to a valid JSON object.
	 */
	public JSONObject getContentAsJSONObject()
		throws ParseException {
		
		ensureContentType(CommonContentTypes.APPLICATION_JSON);
		
		ensureContent();
		
		return JSONObjectUtils.parseJSONObject(content);
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
	
	
	/**
	 * Applies the status code, headers and content of this HTTP response
	 * object to the specified HTTP servlet response.
	 *
	 * @param sr The HTTP servlet response to have the properties of this
	 *           HTTP request applied to. Must not be {@code null}.
	 *
	 * @throws IOException If the response content couldn't be written.
	 */
	public void applyTo(final HttpServletResponse sr)
		throws IOException {
	
		// Set the status code
		sr.setStatus(statusCode);
	
	
		// Set the headers, but only if explicitly specified	
		if (location != null)
			sr.setHeader("Location", location.toString());
		
		if (getContentType() != null)
			sr.setContentType(getContentType().toString());
		
		if (cacheControl != null)
			sr.setHeader("Cache-Control", cacheControl);
		
		if (pragma != null)
			sr.setHeader("Pragma", pragma);
		
		
		if (wwwAuthenticate != null)
			sr.setHeader("Www-Authenticate", wwwAuthenticate);
	
	
		// Write out the content
	
		if (content != null) {
		
			PrintWriter writer = sr.getWriter();
		
			writer.println(content);
			
			writer.close();
		}
	}
}
