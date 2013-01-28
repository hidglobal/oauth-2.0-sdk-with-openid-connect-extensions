package com.nimbusds.oauth2.sdk.http;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import javax.mail.internet.ContentType;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.util.ContentTypeUtils;
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
 * @version $version$ (2013-01-14)
 */
@ThreadSafe
public class HTTPRequest {


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
	 * Specifies a {@code Content-Type} header value.
	 */
	private ContentType contentType = null;
	
	
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
	 * Gets the {@code Content-Type} header value.
	 *
	 * @return The {@code Content-Type} header value, {@code null} if not 
	 *         specified.
	 */
	public ContentType getContentType() {
	
		return contentType;
	}
	
	
	/**
	 * Sets the {@code Content-Type} header value.
	 *
	 * @param ct The {@code Content-Type} header value, {@code null} if not
	 *           specified.
	 */
	public void setContentType(final ContentType ct) {
	
		contentType = ct;
	}
	
	
	/**
	 * Sets the {@code Content-Type} header value.
	 *
	 * @param ct The {@code Content-Type} header value, {@code null} if not
	 *           specified.
	 *
	 * @throws ParseException If the header value couldn't be parsed.
	 */
	public void setContentType(final String ct)
		throws ParseException {
		
		if (ct == null) {
			contentType = null;
			return;
		}
		
		try {
			contentType = new ContentType(ct);
			
		} catch (javax.mail.internet.ParseException e) {
		
			throw new ParseException("Invalid Content-Type header value: " + e.getMessage());
		}
	}
	
	
	/**
	 * Ensures this HTTP request has a specified {@code Content-Type} 
	 * header value.
	 *
	 * @throws ParseException If the {@code Content-Type} header is 
	 *                        missing.
	 */
	public void ensureContentType()
		throws ParseException {
	
		if (contentType == null)
			throw new ParseException("Missing HTTP Content-Type header");
	}
	
	
	/**
	 * Ensures this HTTP request has the specified {@code Content-Type} 
	 * header value. Note that this method compares only the primary type 
	 * and subtype; any content type parameters, such as {@code charset}, 
	 * are ignored.
	 *
	 * @param contentType The expected content type. Must not be 
	 *                    {@code null}.
	 *
	 * @throws ParseException If the {@code Content-Type} header is missing
	 *                        or its primary and subtype doesn't match.
	 */ 
	public void ensureContentType(final ContentType contentType)
		throws ParseException {
		
		ContentTypeUtils.ensureContentType(contentType, getContentType());
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
	 * Gets the request query  as a parameter map. The parameters are 
	 * decoded according to {@code application/x-www-form-urlencoded}.
	 *
	 * @return The request query parameters, decoded. If none the map will
	 *         be empty.
	 */
	public Map<String, String> getQueryParameters() {
	
		return URLUtils.parseParameters(query);
	}
}
