package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * The base abstract class for authorisation success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 * </ul>
 */
public abstract class AuthorizationResponse implements Response {


	/**
	 * The base redirection URI.
	 */
	private final URI redirectURI;


	/**
	 * The optional state parameter to be echoed back to the client.
	 */
	private final State state;


	/**
	 * The optional explicit response mode.
	 */
	private final ResponseMode rm;


	/**
	 * Creates a new authorisation response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 * @param rm          The response mode, {@code null} if not specified.
	 */
	protected AuthorizationResponse(final URI redirectURI, final State state, final ResponseMode rm) {

		if (redirectURI == null) {
			throw new IllegalArgumentException("The redirection URI must not be null");
		}

		this.redirectURI = redirectURI;

		this.state = state;

		this.rm = rm;
	}


	/**
	 * Returns the base redirection URI.
	 *
	 * @return The base redirection URI (without the appended error
	 *         response parameters).
	 */
	public URI getRedirectionURI() {

		return redirectURI;
	}


	/**
	 * Returns the optional state.
	 *
	 * @return The state, {@code null} if not requested.
	 */
	public State getState() {

		return state;
	}


	/**
	 * Returns the optional explicit response mode.
	 *
	 * @return The response mode, {@code null} if not specified.
	 */
	public ResponseMode getResponseMode() {

		return rm;
	}


	/**
	 * Determines the implied response mode.
	 *
	 * @return The implied response mode.
	 */
	public abstract ResponseMode impliedResponseMode();


	/**
	 * Returns the parameters of this authorisation response.
	 *
	 * <p>Example parameters (authorisation success):
	 *
	 * <pre>
	 * access_token = 2YotnFZFEjr1zCsicMWpAA
	 * state = xyz
	 * token_type = example
	 * expires_in = 3600
	 * </pre>
	 *
	 * @return The parameters as a map.
	 *
	 * @throws SerializeException If this response couldn't be serialised
	 *                            to a parameters map.
	 */
	public abstract Map<String,String> toParameters()
		throws SerializeException;


	/**
	 * Returns a URI representation (redirection URI + fragment / query
	 * string) of this authorisation response.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
	 * &amp;state=xyz
	 * &amp;token_type=example
	 * &amp;expires_in=3600
	 * </pre>
	 *
	 * @return A URI representation of this authorisation response.
	 *
	 * @throws SerializeException If this response couldn't be serialised
	 *                            to a URI.
	 */
	public URI toURI()
		throws SerializeException {

		final ResponseMode rm = impliedResponseMode();

		StringBuilder sb = new StringBuilder(getRedirectionURI().toString());

		if (rm.equals(ResponseMode.QUERY)) {
			if (StringUtils.isBlank(getRedirectionURI().getRawQuery())) {
				sb.append('?');
			} else {
				// The original redirect_uri may contain query params,
				// see http://tools.ietf.org/html/rfc6749#section-3.1.2
				sb.append('&');
			}
		} else if (rm.equals(ResponseMode.FRAGMENT)) {
			sb.append('#');
		} else {
			throw new SerializeException("The (implied) response mode must be query or fragment");
		}

		sb.append(URLUtils.serializeParameters(toParameters()));

		try {
			return new URI(sb.toString());

		} catch (URISyntaxException e) {

			throw new SerializeException("Couldn't serialize response: " + e.getMessage(), e);
		}
	}


	/**
	 * Returns an HTTP response for this authorisation response. Applies to
	 * the {@code query} or {@code fragment} response mode using HTTP 302
	 * redirection.
	 *
	 * <p>Example HTTP response (authorisation success):
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
	 * &amp;state=xyz
	 * &amp;token_type=example
	 * &amp;expires_in=3600
	 * </pre>
	 *
	 * @see #toHTTPRequest()
	 *
	 * @return An HTTP response for this authorisation response.
	 *
	 * @throws SerializeException If the response couldn't be serialised to
	 *                            an HTTP response.
	 */
	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {

		if (ResponseMode.FORM_POST.equals(rm)) {
			throw new SerializeException("The response mode must not be form_post");
		}

		HTTPResponse response= new HTTPResponse(HTTPResponse.SC_FOUND);
		response.setLocation(toURI());
		return response;
	}


	/**
	 * Returns an HTTP request for this authorisation response. Applies to
	 * the {@code form_post} response mode.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #toHTTPResponse()
	 *
	 * @return An HTTP request for this authorisation response.
	 *
	 * @throws SerializeException If the response couldn't be serialised to
	 *                            an HTTP request.
	 */
	public HTTPRequest toHTTPRequest()
		throws SerializeException {

		if (! ResponseMode.FORM_POST.equals(rm)) {
			throw new SerializeException("The response mode must be form_post");
		}

		// Use HTTP POST
		HTTPRequest request;

		try {
			request = new HTTPRequest(HTTPRequest.Method.POST, redirectURI.toURL());

		} catch (MalformedURLException e) {
			throw new SerializeException(e.getMessage(), e);
		}

		request.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		request.setQuery(URLUtils.serializeParameters(toParameters()));
		return request;
	}


	/**
	 * Parses an authorisation response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be
	 *                    {@code null}.
	 *
	 * @return The authorisation success or error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation success or error response.
	 */
	public static AuthorizationResponse parse(final URI redirectURI, final Map<String,String> params)
		throws ParseException {

		if (StringUtils.isNotBlank(params.get("error"))) {
			return AuthorizationErrorResponse.parse(redirectURI, params);
		} else {
			return AuthorizationSuccessResponse.parse(redirectURI, params);
		}
	}


	/**
	 * Parses an authorisation response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("http://?code=Qcb0Orv1...&state=af0ifjsldkj");
	 * </pre>
	 *
	 * @param uri The URI to parse. May be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation success or error response.
	 *
	 * @throws ParseException If no authorisation response parameters were
	 *                        found in the URL.
	 */
	public static AuthorizationResponse parse(final URI uri)
		throws ParseException {

		Map<String,String> params;

		if (uri.getRawFragment() != null) {
			params = URLUtils.parseParameters(uri.getRawFragment());
		} else if (uri.getRawQuery() != null) {
			params = URLUtils.parseParameters(uri.getRawQuery());
		} else {
			throw new ParseException("Missing URI fragment or query string");
		}

		return parse(URIUtils.getBaseURI(uri), params);
	}


	/**
	 * Parses an authorisation response from the specified initial HTTP 302
	 * redirect response output at the authorisation endpoint.
	 *
	 * <p>Example HTTP response (authorisation success):
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @see #parse(HTTPRequest)
	 *
	 * @param httpResponse The HTTP response to parse. Must not be
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        authorisation response.
	 */
	public static AuthorizationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		URI location = httpResponse.getLocation();

		if (location == null) {
			throw new ParseException("Missing redirection URI / HTTP Location header");
		}

		return parse(location);
	}


	/**
	 * Parses an authorisation response from the specified HTTP request at
	 * the client redirection (callback) URI. Applies to the {@code query},
	 * {@code fragment} and {@code form_post} response modes.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #parse(HTTPResponse)
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null}.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        authorisation response.
	 */
	public static AuthorizationResponse parse(final HTTPRequest httpRequest)
		throws ParseException {

		final URI baseURI;

		try {
			baseURI = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {
			throw new ParseException(e.getMessage(), e);
		}

		if (httpRequest.getQuery() != null) {
			// For query string and form_post response mode
			return parse(baseURI, URLUtils.parseParameters(httpRequest.getQuery()));
		} else if (httpRequest.getFragment() != null) {
			// For fragment response mode (never available in actual HTTP request from browser)
			return parse(baseURI, URLUtils.parseParameters(httpRequest.getFragment()));
		} else {
			throw new ParseException("Missing URI fragment, query string or post body");
		}
	}
}