package com.nimbusds.openid.connect.sdk.messages;


import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.HTTPResponse;

import com.nimbusds.openid.connect.sdk.util.URLUtils;


/**
 * Authorisation response. This class is immutable.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.org/cb?
 * code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk
 * &state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.3.
 *     <li>OpenID Connect Standard 1.0, section 2.3.5.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-13)
 */
@Immutable
public class AuthorizationResponse implements SuccessResponse {


	/**
	 * The redirect URI.
	 */
	private final URL redirectURI;
	
	
	/**
	 * The authorisation code, if requested.
	 */
	private final AuthorizationCode code;
	
	
	/**
	 * The ID token, if requested.
	 */
	private final JWT idToken;
	
	
	/**
	 * The UserInfo access token, if requested.
	 */
	private final AccessToken accessToken;
	
	
	/**
	 * Optional state, to be echoed back to the client.
	 */
	private final State state;
	
	
	/**
	 * Creates a new authorisation response.
	 *
	 * @param redirectURI The requested redirect URI. Must not be 
	 *                    {@code null}.
	 * @param code        The authorisation code, {@code null} if not 
	 *                    requested.
	 * @param idToken     The ID token (ready for output), {@code null} if 
	 *                    not requested.
	 * @param accessToken The UserInfo access token, {@code null} if not 
	 *                    requested.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthorizationResponse(final URL redirectURI,
	                             final AuthorizationCode code,
				     final JWT idToken,
				     final AccessToken accessToken,
				     final State state) {
	
		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
		
		this.redirectURI = redirectURI;
		
		this.code = code;
		
		this.idToken = idToken;
		
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
	 * Gets the corresponding response type set.
	 *
	 * @return The corresponding response type set.
	 */
	public ResponseTypeSet getResponseTypeSet() {
	
		ResponseTypeSet rts = new ResponseTypeSet();
		
		if (code != null)
			rts.add(ResponseType.CODE);
			
		if (idToken != null)
			rts.add(ResponseType.ID_TOKEN);
		
		if (accessToken != null)
			rts.add(ResponseType.TOKEN);
			
		return rts;
	}
	
	
	/**
	 * Gets the requested authorisation code.
	 *
	 * @return The authorisation code, {@code null} if not requested.
	 */
	public AuthorizationCode getAuthorizationCode() {
	
		return code;
	}
	
	
	/**
	 * Gets the requested ID token.
	 *
	 * @return The ID token (ready for output), {@code null} if not 
	 *         requested.
	 */
	public JWT getIDToken() {
	
		return idToken;
	}
	
	
	/**
	 * Gets the requested UserInfo access token.
	 *
	 * @return The UserInfo access token, {@code null} if not requested.
	 */
	public AccessToken getAccessToken() {
	
		return accessToken;
	}
	
	
	/**
	 * Gets the optional state, if requested to be echoed back to the 
	 * client.
	 *
	 * @return The state, {@code null} if not requested.
	 */
	public State getState() {
	
		return state;
	}
	
	
	/**
	 * Returns the URL representation (redirect URI + fragment / query 
	 * string) of this authorisation response.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * https://client.example.com/cb?code=Qcb0Orv1zh30vL1MPRsbm&state=af0ifjsldkj
	 * </pre>
	 *
	 * @return The URL representation of this authorisation response.
	 *
	 * @throws IllegalStateException If there is no authorisation code, 
	 *                               UserInfo access token or ID token to
	 *                               serialise.
	 * @throws SerializeException    If this response couldn't be serialised
	 *                               to a URL.
	 */
	public URL toURL()
		throws SerializeException {
	
		if (code == null && idToken == null && accessToken == null)
			throw new IllegalStateException("Missing code, access token or ID token");
	
		StringBuilder sb = new StringBuilder(redirectURI.toString());
		
		if (accessToken != null || idToken != null)
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
			
			if (idToken != null) {
			
				if (delimit)
					sb.append('&');
				
				delimit = true;
			
				sb.append("id_token=");
				
				try {
					sb.append(idToken.serialize());
					
				} catch (IllegalStateException e) {
				
					throw new SerializeException("Couldn't serialize ID token: " + e.getMessage(), e);
				
				}
			}
			
			if (accessToken != null) {
			
				if (delimit)
					sb.append('&');
				
				delimit = true;
			
				sb.append("access_token=");
				sb.append(URLEncoder.encode(accessToken.getValue(), "utf-8"));
				sb.append("&token_type=");
				sb.append(AccessToken.TYPE);
				
				final long exp = accessToken.getExpiration();
				
				if (exp > 0) {
					sb.append("&expires_in=");
					sb.append(exp);
				}
				
				Scope scope = accessToken.getScope();
				
				if (scope != null) {
					sb.append("&scope=");
					sb.append(URLEncoder.encode(scope.toString(), "utf-8"));
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
	 * Returns the HTTP response for this authorisation response.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=Qcb0Orv1zh30vL1MPRsbm&state=af0ifjsldkj
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
	 * Parses an authorisation response from the specified absolute or 
	 * relative URL.
	 *
	 * <p>Use a relative URL if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * AuthorizationResponse.parse(new URL("http://?code=Qcb0Orv1...&state=af0ifjsldkj"));
	 * </pre>
	 *
	 * @param url The URL to parse. May be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation response.
	 *
	 * @throws ParseException If no valid authorisation response parameters
	 *                        are found in the URL.
	 */
	public static AuthorizationResponse parse(final URL url)
		throws ParseException {
		
		if (url == null)
			throw new IllegalArgumentException("The URL must not be null");
		
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
		
		
		// Parse id_token parameter
		
		JWT idToken = null;
		
		if (params.get("id_token") != null) {
			
			try {
				idToken = JWTParser.parse(params.get("id_token"));
				
			} catch (java.text.ParseException e) {
			
				throw new ParseException("Invalid ID Token JWT: " + e.getMessage(), e);
			}
		}
		
		
		// Parse access_token parameters
		
		AccessToken accessToken = null;
		
		if (params.get("access_token") != null) {
		
			String accessTokenValue = params.get("access_token");
		
			long exp = -1;
			
			if (params.get("expires_in") != null) {
				
				try {
					exp = new Long(params.get("expires_in"));
					
				} catch (NumberFormatException e) {
				
					throw new ParseException("Invalid expiration time: " + e.getMessage(), e);
				}
			}
			
			Scope scope = null;
			
			if (params.get("scope") != null) {
			
				try {
					scope = Scope.parseStrict(params.get("scope"));
					
				} catch (ParseException e) {
				
					throw new ParseException("Invalid UserInfo scope: " + e.getMessage(), e);
				}
			}
			
			accessToken = new AccessToken(accessTokenValue, exp, scope);
		}
		
		
		// Parse state parameter
		
		State state = null;
		
		if (params.get("state") != null) {
		
			state = new State(params.get("state"));
		}
		
		return new AuthorizationResponse(url, code, idToken, accessToken, state);
	}
}
