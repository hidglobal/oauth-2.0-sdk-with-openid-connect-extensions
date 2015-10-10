package com.nimbusds.oauth2.sdk.http;


import java.io.*;
import java.net.*;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import net.jcip.annotations.ThreadSafe;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * HTTP request with support for the parameters required to construct an 
 * {@link com.nimbusds.oauth2.sdk.Request OAuth 2.0 request message}.
 *
 * <p>Supported HTTP methods:
 *
 * <ul>
 *     <li>{@link Method#GET HTTP GET}
 *     <li>{@link Method#POST HTTP POST}
 *     <li>{@link Method#POST HTTP PUT}
 *     <li>{@link Method#POST HTTP DELETE}
 * </ul>
 *
 * <p>Supported request headers:
 *
 * <ul>
 *     <li>Content-Type
 *     <li>Authorization
 *     <li>Accept
 *     <li>Etc.
 * </ul>
 *
 * <p>Supported timeouts:
 *
 * <ul>
 *     <li>On HTTP connect
 *     <li>On HTTP response read
 * </ul>
 *
 * <p>HTTP 3xx redirection: follow (default) / don't follow
 */
@ThreadSafe
public class HTTPRequest extends HTTPMessage {


	/**
	 * Enumeration of the HTTP methods used in OAuth 2.0 requests.
	 */
	public enum Method {
	
		/**
		 * HTTP GET.
		 */
		GET,
		
		
		/**
		 * HTTP POST.
		 */
		POST,
		
		
		/**
		 * HTTP PUT.
		 */
		PUT,
		
		
		/**
		 * HTTP DELETE.
		 */
		DELETE
	}
	
	
	/**
	 * The request method.
	 */
	private final Method method;


	/**
	 * The request URL.
	 */
	private final URL url;
	
	
	/**
	 * The query string / post body.
	 */
	private String query = null;


	/**
	 * The fragment.
	 */
	private String fragment = null;


	/**
	 * The HTTP connect timeout, in milliseconds. Zero implies none.
	 */
	private int connectTimeout = 0;


	/**
	 * The HTTP response read timeout, in milliseconds. Zero implies none.

	 */
	private int readTimeout = 0;


	/**
	 * Controls HTTP 3xx redirections.
	 */
	private boolean followRedirects = true;


	/**
	 * The default hostname verifier for all HTTPS requests.
	 */
	private static HostnameVerifier defaultHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();


	/**
	 * The default socket factory for all HTTPS requests.
	 */
	private static SSLSocketFactory defaultSSLSocketFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
	
	
	/**
	 * Creates a new minimally specified HTTP request.
	 *
	 * @param method The HTTP request method. Must not be {@code null}.
	 * @param url    The HTTP request URL. Must not be {@code null}.
	 */
	public HTTPRequest(final Method method, final URL url) {
	
		if (method == null)
			throw new IllegalArgumentException("The HTTP method must not be null");
		
		this.method = method;


		if (url == null)
			throw new IllegalArgumentException("The HTTP URL must not be null");

		this.url = url;
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
	 * Gets the request URL.
	 *
	 * @return The request URL.
	 */
	public URL getURL() {

		return url;
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
	
		return getHeader("Authorization");
	}
	
	
	/**
	 * Sets the {@code Authorization} header value.
	 *
	 * @param authz The {@code Authorization} header value, {@code null} if 
	 *              not specified.
	 */
	public void setAuthorization(final String authz) {
	
		setHeader("Authorization", authz);
	}


	/**
	 * Gets the {@code Accept} header value.
	 *
	 * @return The {@code Accept} header value, {@code null} if not
	 *         specified.
	 */
	public String getAccept() {

		return getHeader("Accept");
	}


	/**
	 * Sets the {@code Accept} header value.
	 *
	 * @param accept The {@code Accept} header value, {@code null} if not
	 *               specified.
	 */
	public void setAccept(final String accept) {

		setHeader("Accept", accept);
	}
	
	
	/**
	 * Gets the raw (undecoded) query string if the request is HTTP GET or
	 * the entity body if the request is HTTP POST.
	 *
	 * <p>Note that the '?' character preceding the query string in GET
	 * requests is not included in the returned string.
	 *
	 * <p>Example query string (line breaks for clarity):
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
	 * <p>Example query string (line breaks for clarity):
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
		
		if (query == null || query.trim().isEmpty())
			throw new ParseException("Missing or empty HTTP query string / entity body");
	}
	
	
	/**
	 * Gets the request query as a parameter map. The parameters are 
	 * decoded according to {@code application/x-www-form-urlencoded}.
	 *
	 * @return The request query parameters, decoded. If none the map will
	 *         be empty.
	 */
	public Map<String,String> getQueryParameters() {
	
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

		return JSONObjectUtils.parse(query);
	}


	/**
	 * Gets the raw (undecoded) request fragment.
	 *
	 * @return The request fragment, {@code null} if not specified.
	 */
	public String getFragment() {

		return fragment;
	}


	/**
	 * Sets the raw (undecoded) request fragment.
	 *
	 * @param fragment The request fragment, {@code null} if not specified.
	 */
	public void setFragment(final String fragment) {

		this.fragment = fragment;
	}


	/**
	 * Gets the HTTP connect timeout.
	 *
	 * @return The HTTP connect read timeout, in milliseconds. Zero implies
	 *         no timeout.
	 */
	public int getConnectTimeout() {

		return connectTimeout;
	}


	/**
	 * Sets the HTTP connect timeout.
	 *
	 * @param connectTimeout The HTTP connect timeout, in milliseconds.
	 *                       Zero implies no timeout. Must not be negative.
	 */
	public void setConnectTimeout(final int connectTimeout) {

		if (connectTimeout < 0) {
			throw new IllegalArgumentException("The HTTP connect timeout must be zero or positive");
		}

		this.connectTimeout = connectTimeout;
	}


	/**
	 * Gets the HTTP response read timeout.
	 *
	 * @return The HTTP response read timeout, in milliseconds. Zero
	 *         implies no timeout.
	 */
	public int getReadTimeout() {

		return readTimeout;
	}


	/**
	 * Sets the HTTP response read timeout.
	 *
	 * @param readTimeout The HTTP response read timeout, in milliseconds.
	 *                    Zero implies no timeout. Must not be negative.
	 */
	public void setReadTimeout(final int readTimeout) {

		if (readTimeout < 0) {
			throw new IllegalArgumentException("The HTTP response read timeout must be zero or positive");
		}

		this.readTimeout = readTimeout;
	}


	/**
	 * Gets the boolean setting whether HTTP redirects (requests with
	 * response code 3xx) should be automatically followed.
	 *
	 * @return {@code true} if HTTP redirects are automatically followed,
	 *         else {@code false}.
	 */
	public boolean getFollowRedirects() {

		return followRedirects;
	}


	/**
	 * Sets whether HTTP redirects (requests with response code 3xx) should
	 * be automatically followed.
	 *
	 * @param follow Whether or not to follow HTTP redirects.
	 */
	public void setFollowRedirects(final boolean follow) {

		followRedirects = follow;
	}


	/**
	 * Returns the default hostname verifier for all HTTPS requests.
	 *
	 * @return The hostname verifier.
	 */
	public static HostnameVerifier getDefaultHostnameVerifier() {

		return defaultHostnameVerifier;
	}


	/**
	 * Sets the default hostname verifier for all HTTPS requests. May be
	 * overridden on a individual request basis.
	 *
	 * @param defaultHostnameVerifier The hostname verifier. Must not be
	 *                         {@code null}.
	 */
	public static void setDefaultHostnameVerifier(final HostnameVerifier defaultHostnameVerifier) {

		if (defaultHostnameVerifier == null) {
			throw new IllegalArgumentException("The hostname verifier must not be null");
		}

		HTTPRequest.defaultHostnameVerifier = defaultHostnameVerifier;
	}


	/**
	 * Returns the default SSL socket factory for all HTTPS requests.
	 *
	 * @return The SSL socket factory.
	 */
	public static SSLSocketFactory getDefaultSSLSocketFactory() {

		return defaultSSLSocketFactory;
	}


	/**
	 * Sets the default SSL socket factory for all HTTPS requests. May be
	 * overridden on a individual request basis.
	 *
	 * @param sslSocketFactory The SSL socket factory. Must not be
	 *                         {@code null}.
	 */
	public static void setDefaultSSLSocketFactory(final SSLSocketFactory sslSocketFactory) {

		if (sslSocketFactory == null) {
			throw new IllegalArgumentException("The SSL socket factory must not be null");
		}

		HTTPRequest.defaultSSLSocketFactory = sslSocketFactory;
	}


	/**
	 * Returns an established HTTP URL connection for this HTTP request.
	 *
	 * @return The HTTP URL connection, with the request sent and ready to
	 *         read the response.
	 *
	 * @throws IOException If the HTTP request couldn't be made, due to a
	 *                     network or other error.
	 */
	public HttpURLConnection toHttpURLConnection()
		throws IOException {

		return toHttpURLConnection(null, null);
	}


	/**
	 * Returns an established HTTP URL connection for this HTTP request.
	 *
	 * @param hostnameVerifier The hostname verifier for HTTPS requests.
	 *                         Disregarded for plain HTTP requests. If
	 *                         {@code null} the
	 *                         {@link #getDefaultHostnameVerifier() default
	 *                         hostname verifier} will apply.
	 * @param sslSocketFactory The SSL socket factory for HTTPS requests.
	 *                         Disregarded for plain HTTP requests. If
	 *                         {@code null} the
	 *                         {@link #getDefaultSSLSocketFactory() default
	 *                         SSL socket factory} will apply.
	 *
	 * @return The HTTP URL connection, with the request sent and ready to
	 *         read the response.
	 *
	 * @throws IOException If the HTTP request couldn't be made, due to a
	 *                     network or other error.
	 */
	public HttpURLConnection toHttpURLConnection(final HostnameVerifier hostnameVerifier,
						     final SSLSocketFactory sslSocketFactory)
		throws IOException {

		URL finalURL = url;

		if (query != null && (method.equals(HTTPRequest.Method.GET) || method.equals(Method.DELETE))) {

			// Append query string
			StringBuilder sb = new StringBuilder(url.toString());
			sb.append('?');
			sb.append(query);

			try {
				finalURL = new URL(sb.toString());

			} catch (MalformedURLException e) {

				throw new IOException("Couldn't append query string: " + e.getMessage(), e);
			}
		}

		if (fragment != null) {

			// Append raw fragment
			StringBuilder sb = new StringBuilder(finalURL.toString());
			sb.append('#');
			sb.append(fragment);

			try {
				finalURL = new URL(sb.toString());

			} catch (MalformedURLException e) {

				throw new IOException("Couldn't append raw fragment: " + e.getMessage(), e);
			}
		}

		HttpURLConnection conn = (HttpURLConnection)finalURL.openConnection();

		if (conn instanceof HttpsURLConnection) {
			HttpsURLConnection sslConn = (HttpsURLConnection)conn;
			sslConn.setHostnameVerifier(hostnameVerifier != null ? hostnameVerifier : getDefaultHostnameVerifier());
			sslConn.setSSLSocketFactory(sslSocketFactory != null ? sslSocketFactory : getDefaultSSLSocketFactory());
		}

		for (Map.Entry<String,String> header: getHeaders().entrySet()) {
			conn.setRequestProperty(header.getKey(), header.getValue());
		}

		conn.setRequestMethod(method.name());
		conn.setConnectTimeout(connectTimeout);
		conn.setReadTimeout(readTimeout);
		conn.setInstanceFollowRedirects(followRedirects);

		if (method.equals(HTTPRequest.Method.POST) || method.equals(Method.PUT)) {

			conn.setDoOutput(true);

			if (getContentType() != null)
				conn.setRequestProperty("Content-Type", getContentType().toString());

			if (query != null) {
				OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
				writer.write(query);
				writer.close();
			}
		}

		return conn;
	}


	/**
	 * Sends this HTTP request to the request URL and retrieves the 
	 * resulting HTTP response.
	 *
	 * @return The resulting HTTP response.
	 *
	 * @throws IOException If the HTTP request couldn't be made, due to a 
	 *                     network or other error.
	 */
	public HTTPResponse send()
		throws IOException {

		return send(null, null);
	}


	/**
	 * Sends this HTTP request to the request URL and retrieves the
	 * resulting HTTP response.
	 *
	 * @param hostnameVerifier The hostname verifier for HTTPS requests.
	 *                         Disregarded for plain HTTP requests. If
	 *                         {@code null} the
	 *                         {@link #getDefaultHostnameVerifier() default
	 *                         hostname verifier} will apply.
	 * @param sslSocketFactory The SSL socket factory for HTTPS requests.
	 *                         Disregarded for plain HTTP requests. If
	 *                         {@code null} the
	 *                         {@link #getDefaultSSLSocketFactory() default
	 *                         SSL socket factory} will apply.
	 *
	 * @return The resulting HTTP response.
	 *
	 * @throws IOException If the HTTP request couldn't be made, due to a
	 *                     network or other error.
	 */
	public HTTPResponse send(final HostnameVerifier hostnameVerifier,
				 final SSLSocketFactory sslSocketFactory)
		throws IOException {

		HttpURLConnection conn = toHttpURLConnection(hostnameVerifier, sslSocketFactory);

		int statusCode;

		BufferedReader reader;

		try {
			// Open a connection, then send method and headers
			reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));

			// The next step is to get the status
			statusCode = conn.getResponseCode();

		} catch (IOException e) {

			// HttpUrlConnection will throw an IOException if any
			// 4XX response is sent. If we request the status
			// again, this time the internal status will be
			// properly set, and we'll be able to retrieve it.
			statusCode = conn.getResponseCode();

			if (statusCode == -1) {
				// Rethrow IO exception
				throw e;
			} else {
				// HTTP status code indicates the response got
				// through, read the content but using error stream
				InputStream errStream = conn.getErrorStream();

				if (errStream != null) {
					// We have useful HTTP error body
					reader = new BufferedReader(new InputStreamReader(errStream));
				} else {
					// No content, set to empty string
					reader = new BufferedReader(new StringReader(""));
				}
			}
		}

		StringBuilder body = new StringBuilder();

		try {
			String line;

			while ((line = reader.readLine()) != null) {
				body.append(line);
				body.append(System.getProperty("line.separator"));
			}

			reader.close();

		} finally {
			conn.disconnect();
		}


		HTTPResponse response = new HTTPResponse(statusCode);

		String location = conn.getHeaderField("Location");

		if (location != null) {

			try {
				response.setLocation(new URI(location));

			} catch (URISyntaxException e) {
				throw new IOException("Couldn't parse Location header: " + e.getMessage(), e);
			}
		}


		try {
			response.setContentType(conn.getContentType());

		} catch (ParseException e) {

			throw new IOException("Couldn't parse Content-Type header: " + e.getMessage(), e);
		}


		response.setCacheControl(conn.getHeaderField("Cache-Control"));

		response.setPragma(conn.getHeaderField("Pragma"));

		response.setWWWAuthenticate(conn.getHeaderField("WWW-Authenticate"));

		String bodyContent = body.toString();

		if (! bodyContent.isEmpty())
			response.setContent(bodyContent);


		return response;
	}
}
