package com.nimbusds.oauth2.sdk;


import java.io.UnsupportedEncodingException;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;

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
 * https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.2 and 4.2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-17)
 */
@Immutable
public class AuthorizationSuccessResponse 
	extends AuthorizationResponse 
	implements OAuth2SuccessResponse {


	/**
	 * The redirect URI.
	 */
	private final URL redirectURI;
	
	
	/**
	 * The authorisation code, if requested.
	 */
	private final AuthorizationCode code;
	
	
	/**
	 * The access token, if requested.
	 */
	private final AccessToken accessToken;
	
	
	/**
	 * Optional state, to be echoed back to the client.
	 */
	private final State state;


	/**
	 * Creates a new authorisation success response in the code flow 
	 * (authorisation code grant).
	 *
	 * @param redirectURI The requested redirect URI. Must not be 
	 *                    {@code null}.
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
	 * @param redirectURI The requested redirect URI. Must not be 
	 *                    {@code null}.
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
	 * @param redirectURI The requested redirect URI. Must not be 
	 *                    {@code null}.
	 * @param code        The authorisation code, {@code null} if not 
	 *                    requested.
	 * @param accessToken The access token, {@code null} if not requested.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthorizationSuccessResponse(final URL redirectURI,
	                                    final AuthorizationCode code,
				            final AccessToken accessToken,
				            final State state) {
	
		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
		
		this.redirectURI = redirectURI;
		
		this.code = code;
		
		this.accessToken = accessToken;
		
		this.state = state;
	}
	
	
	/**
	 * Gets the requested redirect URI.
	 *
	 * @return The requested redirect URI.
	 */
	public URL getRedirectURI() {
	
		return redirectURI;
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
	
	
	/**
	 * Gets the optional state.
	 *
	 * @return The state, {@code null} if not requested.
	 */
	public State getState() {
	
		return state;
	}
	
	
	/**
	 * Returns the URL representation (redirect URI + fragment / query 
	 * string) of this authorisation success response.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
	 * &amp;state=xyz
	 * &amp;token_type=example
	 * &amp;expires_in=3600
	 * </pre>
	 *
	 * @return The URL representation of this authorisation response.
	 *
	 * @throws IllegalStateException If there is no authorisation code or 
	 *                               access token to serialise.
	 * @throws SerializeException    If this response couldn't be 
	 *                               serialised to a URL.
	 */
	public URL toURL()
		throws SerializeException {
	
		if (code == null && accessToken == null)
			throw new IllegalStateException("Missing code or access token");
	
		StringBuilder sb = new StringBuilder(redirectURI.toString());
		
		// Fragment or query string?
		if (accessToken != null)
			sb.append('#');
		else
			sb.append('?');
		
		try {
			boolean delimit = false;
		
			if (code != null) {
				sb.append("code=");
				sb.append(URLEncoder.encode(code.getValue(), "utf-8"));
				
				delimit = true;
			}
			
			if (accessToken != null) {
			
				for (Map.Entry<String,Object> entry: accessToken.toJSONObject().entrySet()) {

					if (delimit)
						sb.append('&');

					delimit = true;

					sb.append(entry.getKey());
					sb.append('=');

					Object value = entry.getValue();

					if (value == null)
						break;

					else if (value instanceof String)
						sb.append(URLEncoder.encode((String)value, "utf-8"));

					else
						sb.append(value.toString());
				}
			}
			
			if (state != null) {
			
				if (delimit)
					sb.append('&');
				
				sb.append("state=");
				sb.append(URLEncoder.encode(state.toString(), "utf-8"));
			}
			
			return new URL(sb.toString());
		
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
			throw new SerializeException("Couldn't serialize response: " + e.getMessage(), e);
			
		} catch (MalformedURLException e) {
		
			throw new SerializeException("Couldn't serialize response: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Returns the HTTP response for this authorisation success response.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
	 * &amp;state=xyz
	 * &amp;token_type=example
	 * &amp;expires_in=3600
	 * </pre>
	 *
	 * @return The HTTP response matching this authorisation response.
	 *
	 * @throws SerializeException If the response couldn't be serialised to
	 *                            an HTTP response.
	 */
	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse response = new HTTPResponse(HTTPResponse.SC_FOUND);
		
		response.setLocation(toURL());
		
		return response;
	}
	
	
	/**
	 * Parses an authorisation success response from the specified absolute
	 * or relative URL.
	 *
	 * <p>Use a relative URL if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * AuthorizationSuccessResponse.parse(new URL("http://?code=Qcb0Orv1...&state=af0ifjsldkj"));
	 * </pre>
	 *
	 * @param url The URL to parse. May be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If no authorisation response parameters were
	 *                        found in the URL.
	 */
	public static AuthorizationSuccessResponse parse(final URL url)
		throws ParseException {
		
		String paramString = null;
		
		try {
			if (url.getQuery() != null)
				paramString = URLDecoder.decode(url.getQuery(), "utf-8");
				
			else if (url.getRef() != null)
				paramString = URLDecoder.decode(url.getRef(), "utf-8");
			else
				throw new ParseException("Missing authorization response parameters");
			
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
			throw new ParseException("Couldn't decode URL: " + e.getMessage(), e);
		}
			
		
		Map<String,String> params = URLUtils.parseParameters(paramString);
		
		if (params == null)
			throw new ParseException("Missing or invalid authorization response parameters");
		
		
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
		
		return new AuthorizationSuccessResponse(url, code, accessToken, state);
	}
}
