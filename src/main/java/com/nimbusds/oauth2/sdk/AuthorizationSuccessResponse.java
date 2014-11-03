package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
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
	 * Creates a new authorisation success response in the code flow 
	 * (authorisation code grant).
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param code        The authorisation code. Must not be {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthorizationSuccessResponse(final URI redirectURI,
	                                    final AuthorizationCode code,
				            final State state) {
	
		this(redirectURI, code, null, state);

		if (code == null)
			throw new IllegalArgumentException("The authorization code must not be null");
	}


	/**
	 * Creates a new authorisation success response in the implicit flow 
	 * (implicit grant).
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param accessToken The access token. Must not be {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthorizationSuccessResponse(final URI redirectURI,
				            final AccessToken accessToken,
				            final State state) {
	
		this(redirectURI, null, accessToken, state);

		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");
	}
	
	
	/**
	 * Creates a new authorisation success response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param code        The authorisation code, {@code null} if not 
	 *                    requested.
	 * @param accessToken The access token, {@code null} if not requested.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthorizationSuccessResponse(final URI redirectURI,
	                                    final AuthorizationCode code,
				            final AccessToken accessToken,
				            final State state) {
	
		super(redirectURI, state);
		this.code = code;
		this.accessToken = accessToken;
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
	
	
	@Override
	public URI toURI()
		throws SerializeException {
	
		StringBuilder sb = new StringBuilder(getRedirectionURI().toString());
		
		// Fragment or query string?
		if (accessToken != null) {
			sb.append('#');
		} else {
			sb.append('?');
		}
		
		sb.append(URLUtils.serializeParameters(toParameters()));

		try {
			return new URI(sb.toString());
			
		} catch (URISyntaxException e) {
		
			throw new SerializeException("Couldn't serialize response: " + e.getMessage(), e);
		}
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
		
		if (params.get("code") != null)
			code = new AuthorizationCode(params.get("code"));
		
		// Parse access_token parameters
		
		AccessToken accessToken = null;
		
		if (params.get("access_token") != null) {

			JSONObject jsonObject = new JSONObject();
			jsonObject.putAll(params);
			accessToken = AccessToken.parse(jsonObject);
		}
		
		// Parse optional state parameter
		State state = State.parse(params.get("state"));
		
		return new AuthorizationSuccessResponse(redirectURI, code, accessToken, state);
	}
	
	
	/**
	 * Parses an authorisation success response.
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
		
		String paramString;
		
		if (uri.getQuery() != null) {

			paramString = uri.getRawQuery();

		} else if (uri.getRawFragment() != null) {

			paramString = uri.getRawFragment();

		} else {

			throw new ParseException("Missing authorization response parameters");
		}
		
		Map<String,String> params = URLUtils.parseParameters(paramString);

		if (params == null)
			throw new ParseException("Missing or invalid authorization response parameters");

		return parse(URIUtils.getBaseURI(uri), params);
	}


	/**
	 * Parses an authorisation success response.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
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
		
		if (httpResponse.getStatusCode() != HTTPResponse.SC_FOUND)
			throw new ParseException("Unexpected HTTP status code, must be 302 (Found): " + 
			                         httpResponse.getStatusCode());
		
		URI location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirection URL / HTTP Location header");

		return parse(location);
	}
}
