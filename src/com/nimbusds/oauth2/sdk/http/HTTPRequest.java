package com.nimbusds.oauth2.sdk.http;


import java.io.BufferedReader;
import java.io.IOException;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import net.jcip.annotations.ThreadSafe;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.util.ContentTypeUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * HTTP request with support for all parameters required to construct an 
 * {@link com.nimbusds.oauth2.sdk.Request OAuth 2.0 request message}. This
 * class is thread-safe.
 *
 * <p>Supported HTTP methods:
 *
 * <ul>
 *     <li>{@link Method#GET HTTP GET}
 *     <li>{@link Method#POST HTTP POST}
 * </ul>
 *
 * <p>Supported request headers:
 *
 * <ul>
 *     <li>Content-Type
 *     <li>Authorization
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-18)
 */
@ThreadSafe
public class HTTPRequest extends HTTPMessage {


	/**
	 * Enumeration of the HTTP methods used in OAuth 2.0 requests.
	 */
	public static enum Method {
	
		/**
		 * HTTP GET.
		 */
		GET,
		
		
		/**
		 * HTTP POST.
		 */
		POST
	}
	
	
	/**
	 * The request method.
	 */
	private final Method method;
	
	
	/**
	 * Specifies an {@code Authorization} header value.
	 */
	private String authorization = null;
	
	
	/**
	 * The query string / post body.
	 */
	private String query = null;
	
	
	/**
	 * Creates a new minimally specified HTTP request.
	 *
	 * @param method The HTTP request method. Must not be {@code null}.
	 */
	public HTTPRequest(final Method method) {
	
		if (method == null)
			throw new IllegalArgumentException("The HTTP method must not be null");
		
		this.method = method;
	}
	
	
	/**
	 * Creates a new HTTP request from the specified HTTP servlet request.
	 *
	 * @param sr The servlet request. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException The the servlet request method is
	 *                                  not GET or POST, or the content type
	 *                                  header value couldn't be parsed.
	 * @throws IOException              For a POST body that couldn't be 
	 *                                  read due to an I/O exception.
	 */
	public HTTPRequest(final HttpServletRequest sr)
		throws IOException {
	
		method = HTTPRequest.Method.valueOf(sr.getMethod().toUpperCase());
		
		String ct = sr.getContentType();
		
		try {
			setContentType(sr.getContentType());
		
		} catch (ParseException e) {
			
			throw new IllegalArgumentException("Invalid Content-Type header value: " + e.getMessage(), e);
		}
		
		setAuthorization(sr.getHeader("Authorization"));
		
		if (method.equals(Method.GET)) {
		
			setQuery(sr.getQueryString());
		}
		else if (method.equals(Method.POST)) {
		
			// read body
			
			StringBuilder body = new StringBuilder(256);
			
			BufferedReader reader = sr.getReader();
			
			String line = null;
			
			while ((line = reader.readLine()) != null) {
			
				body.append(line);
				body.append(System.getProperty("line.separator"));
			}
			
			reader.close();
			
			setQuery(body.toString());
		}
	}
	
	
	/**
	 * Gets the request method.
	 *
	 * @return The request method.
	 */
	public Method getMethod() {
	
		return method;
	}
	
	
	/**
	 * Ensures this HTTP request has the specified method.
	 *
	 * @param expectedMethod The expected method. Must not be {@code null}.
	 *
	 * @throws ParseException If the method doesn't match the expected.
	 */
	public void ensureMethod(final Method expectedMethod)
		throws ParseException {
		
		if (method != expectedMethod)
			throw new ParseException("The HTTP request method must be " + expectedMethod);
	}
	
	
	/**
	 * Gets the {@code Authorization} header value.
	 *
	 * @return The {@code Authorization} header value, {@code null} if not 
	 *         specified.
	 */
	public String getAuthorization() {
	
		return authorization;
	}
	
	
	/**
	 * Sets the {@code Authorization} header value.
	 *
	 * @param authz The {@code Authorization} header value, {@code null} if 
	 *              not specified.
	 */
	public void setAuthorization(final String authz) {
	
		authorization = authz;
	}
	
	
	/**
	 * Gets the raw (undecoded) query string if the request is HTTP GET or
	 * the entity body if the request is HTTP POST.
	 *
	 * <p>Note that the '?' character preceding the query string in GET
	 * requests is not included in the returned string.
	 *
	 * <p>Example query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @return For HTTP GET requests the URL query string, for HTTP POST 
	 *         requests the body. {@code null} if not specified.
	 */
	public String getQuery() {
	
		return query;
	}
	
	
	/**
	 * Sets the raw (undecoded) query string if the request is HTTP GET or
	 * the entity body if the request is HTTP POST.
	 *
	 * <p>Note that the '?' character preceding the query string in GET
	 * requests must not be included.
	 *
	 * <p>Example query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param query For HTTP GET requests the URL query string, for HTTP 
	 *              POST requests the body. {@code null} if not specified.
	 */
	public void setQuery(final String query) {
	
		this.query = query;
	}


	/**
	 * Ensures this HTTP response has a specified query string or entity
	 * body.
	 *
	 * @throws ParseException If the query string or entity body is missing
	 *                        or empty.
	 */
	private void ensureQuery()
		throws ParseException {
		
		if (query == null || query.isEmpty())
			throw new ParseException("Missing or empty HTTP query string / entity body");
	}
	
	
	/**
	 * Gets the request query as a parameter map. The parameters are 
	 * decoded according to {@code application/x-www-form-urlencoded}.
	 *
	 * @return The request query parameters, decoded. If none the map will
	 *         be empty.
	 */
	public Map<String, String> getQueryParameters() {
	
		return URLUtils.parseParameters(query);
	}


	/**
	 * Gets the request query or entity body as a JSON Object.
	 *
	 * @return The request query or entity body as a JSON object.
	 *
	 * @throws ParseException If the Content-Type header isn't 
	 *                        {@code application/json}, the request query
	 *                        or entity body is {@code null}, empty or 
	 *                        couldn't be parsed to a valid JSON object.
	 */
	public JSONObject getQueryAsJSONObject()
		throws ParseException {

		ensureContentType(CommonContentTypes.APPLICATION_JSON);

		ensureQuery();

		return JSONObjectUtils.parseJSONObject(query);
	}
}
