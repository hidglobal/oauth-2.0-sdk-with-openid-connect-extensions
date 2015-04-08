package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Authorisation success response. Used to return an authorisation code or 
 * access token at the Authorisation endpoint.
 *
 * <p>Example HTTP response with code (code flow):
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
 * </pre>
 *
 * <p>Example HTTP response with access token (implicit flow):
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
 *           &amp;state=xyz&amp;token_type=Bearer&amp;expires_in=3600
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.2 and 4.2.2.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode (draft 04).
 * </ul>
 */
@Immutable
public class AuthorizationSuccessResponse 
	extends AuthorizationResponse 
	implements SuccessResponse {
	
	
	/**
	 * The authorisation code, if requested.
	 */
	private final AuthorizationCode code;
	
	
	/**
	 * The access token, if requested.
	 */
	private final AccessToken accessToken;
	
	
	/**
	 * Creates a new authorisation success response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param code        The authorisation code, {@code null} if not 
	 *                    requested.
	 * @param accessToken The access token, {@code null} if not requested.
	 * @param state       The state, {@code null} if not specified.
	 * @param rm          The response mode, {@code null} if not specified.
	 */
	public AuthorizationSuccessResponse(final URI redirectURI,
	                                    final AuthorizationCode code,
				            final AccessToken accessToken,
				            final State state,
					    final ResponseMode rm) {
	
		super(redirectURI, state, rm);
		this.code = code;
		this.accessToken = accessToken;
	}


	@Override
	public boolean indicatesSuccess() {

		return true;
	}
	
	
	/**
	 * Returns the implied response type.
	 *
	 * @return The implied response type.
	 */
	public ResponseType impliedResponseType() {
	
		ResponseType rt = new ResponseType();
		
		if (code != null)
			rt.add(ResponseType.Value.CODE);
		
		if (accessToken != null)
			rt.add(ResponseType.Value.TOKEN);
			
		return rt;
	}


	@Override
	public ResponseMode impliedResponseMode() {

		if (getResponseMode() != null) {
			return getResponseMode();
		} else {
			if (accessToken != null) {
				return ResponseMode.FRAGMENT;
			} else {
				return ResponseMode.QUERY;
			}
		}
	}
	
	
	/**
	 * Gets the authorisation code.
	 *
	 * @return The authorisation code, {@code null} if not requested.
	 */
	public AuthorizationCode getAuthorizationCode() {
	
		return code;
	}
	
	
	/**
	 * Gets the access token.
	 *
	 * @return The access token, {@code null} if not requested.
	 */
	public AccessToken getAccessToken() {
	
		return accessToken;
	}


	@Override
	public Map<String,String> toParameters()
		throws SerializeException {

		Map<String,String> params = new HashMap<>();

		if (code != null)
			params.put("code", code.getValue());

		if (accessToken != null) {
			
			for (Map.Entry<String,Object> entry: accessToken.toJSONObject().entrySet()) {

				params.put(entry.getKey(), entry.getValue().toString());
			}
		}
			
		if (getState() != null)
			params.put("state", getState().getValue());

		return params;
	}


	/**
	 * Parses an authorisation success response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final URI redirectURI,
		                                         final Map<String,String> params)
		throws ParseException {
	
		// Parse code parameter
		
		AuthorizationCode code = null;
		
		if (params.get("code") != null) {
			code = new AuthorizationCode(params.get("code"));
		}
		
		// Parse access_token parameters
		
		AccessToken accessToken = null;
		
		if (params.get("access_token") != null) {

			JSONObject jsonObject = new JSONObject();
			jsonObject.putAll(params);
			accessToken = AccessToken.parse(jsonObject);
		}
		
		// Parse optional state parameter
		State state = State.parse(params.get("state"));
		
		return new AuthorizationSuccessResponse(redirectURI, code, accessToken, state, null);
	}
	
	
	/**
	 * Parses an authorisation success response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("http://?code=Qcb0Orv1...&state=af0ifjsldkj");
	 * </pre>
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If the redirection URI couldn't be parsed to
	 *                        an authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final URI uri)
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
	 * Parses an authorisation success response from the specified initial
	 * HTTP 302 redirect response generated at the authorisation endpoint.
	 *
	 * <p>Example HTTP response:
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
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		URI location = httpResponse.getLocation();
		
		if (location == null) {
			throw new ParseException("Missing redirection URL / HTTP Location header");
		}

		return parse(location);
	}


	/**
	 * Parses an authorisation success response from the specified HTTP
	 * request at the client redirection (callback) URI. Applies to
	 * {@code query}, {@code fragment} and {@code form_post} response
	 * modes.
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
	 *                        authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final HTTPRequest httpRequest)
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
