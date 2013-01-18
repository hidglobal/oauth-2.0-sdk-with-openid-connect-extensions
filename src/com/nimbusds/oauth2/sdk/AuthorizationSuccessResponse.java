package com.nimbusds.oauth2.sdk;


import java.io.UnsupportedEncodingException;

import java.net.MalformedURLException;
import java.net.URL;

import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.oauth2.sdk.token.AccessToken;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Authorisation success response. Used to return an authorization code or 
 * access token at the Authorisation endpoint. This class is immutable.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.2 and 4.2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-18)
 */
@Immutable
public class AuthorizationSuccessResponse 
	extends AuthorizationResponse 
	implements OAuth2SuccessResponse {
	
	
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
	 * @param redirectURI The base redirect URI. Must not be {@code null}.
	 * @param code        The authorisation code. Must not be {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthorizationSuccessResponse(final URL redirectURI,
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
	 * @param redirectURI The base redirect URI. Must not be {@code null}.
	 * @param accessToken The access token. Must not be {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthorizationSuccessResponse(final URL redirectURI,
				            final AccessToken accessToken,
				            final State state) {
	
		this(redirectURI, null, accessToken, state);

		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");
	}
	
	
	/**
	 * Creates a new authorisation success response.
	 *
	 * @param redirectURI The base redirect URI. Must not be {@code null}.
	 * @param code        The authorisation code, {@code null} if not 
	 *                    requested.
	 * @param accessToken The access token, {@code null} if not requested.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthorizationSuccessResponse(final URL redirectURI,
	                                    final AuthorizationCode code,
				            final AccessToken accessToken,
				            final State state) {
	
		super(redirectURI, state);
		
		this.code = code;
		
		this.accessToken = accessToken;
	}
	
	
	/**
	 * Gets the implied response type set.
	 *
	 * @return The implied response type set.
	 */
	public ResponseTypeSet getImpliedResponseTypeSet() {
	
		ResponseTypeSet rts = new ResponseTypeSet();
		
		if (code != null)
			rts.add(ResponseType.CODE);
		
		if (accessToken != null)
			rts.add(ResponseType.TOKEN);
			
		return rts;
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
	public Map<String,String> toParameters() {

		Map<String,String> params = new HashMap<String,String>();

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
	 * {@inheritDoc}
	 *
	 * @throws IllegalStateException If there is no authorisation code or 
	 *                               access token to serialise.
	 */
	@Override
	public URL toURI()
		throws SerializeException {
	
		if (code == null && accessToken == null)
			throw new IllegalStateException("Missing code or access token");
	
		StringBuilder sb = new StringBuilder(getRedirectURI().toString());
		
		// Fragment or query string?
		if (accessToken != null)
			sb.append('#');
		else
			sb.append('?');
		
		
		sb.append(URLUtils.serializeParameters(toParameters()));


		try {
			return new URL(sb.toString());
			
		} catch (MalformedURLException e) {
		
			throw new SerializeException("Couldn't serialize response: " + e.getMessage(), e);
		}
	}


	/**
	 * Parses an authorisation success response.
	 *
	 * @param redirectURI The base redirect URI. Must not be {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final URL redirectURI, 
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
	 * @throws ParseException If the redirect URI couldn't be parsed to an
	 *                        authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final URL uri)
		throws ParseException {
		
		String paramString = null;
		
		if (uri.getQuery() != null)
			paramString = uri.getQuery();
				
		else if (uri.getRef() != null)
			paramString = uri.getRef();
		
		else
			throw new ParseException("Missing authorization response parameters");
		
		Map<String,String> params = URLUtils.parseParameters(paramString);

		if (params == null)
			throw new ParseException("Missing or invalid authorization response parameters");

		return parse(URLUtils.getBaseURL(uri), params);
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
		
		URL location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirect URL / HTTP Location header");
		
		return parse(location);
	}
}
