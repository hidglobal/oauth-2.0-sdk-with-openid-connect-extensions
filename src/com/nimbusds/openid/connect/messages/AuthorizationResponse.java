package com.nimbusds.openid.connect.messages;


import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Map;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTException;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.HTTPResponse;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Authorisation response.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-13)
 */
public class AuthorizationResponse implements SuccessResponse {


	/**
	 * The redirecton URI.
	 */
	private URL redirectURI;
	
	
	/**
	 * The authorisation code, if requested.
	 */
	private AuthorizationCode code;
	
	
	/**
	 * The UserInfo access token, if requested.
	 */
	private AccessToken accessToken = null;
	
	
	/**
	 * The ID token, if requested.
	 */
	private JWT idToken = null;
	
	
	/**
	 * Optional state, to be echoed back to the client.
	 */
	private State state = null;
	
	
	/**
	 * Creates a new authorisation response. It must then be set with the
	 * requested {@link #setAuthorizationCode code}, 
	 * {@link #setAccessToken UserInfo access token} and / or 
	 * {@link #setIDToken ID token}.
	 *
	 * @param redirectURI The requested redirect URI. Must not be 
	 *                    {@code null}.
	 */
	public AuthorizationResponse(final URL redirectURI) {
	
		if (redirectURI == null)
			throw new NullPointerException("The redirect URI must not be null");
		
		this.redirectURI = redirectURI;
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
	 * Sets the requested authorisation code.
	 *
	 * @param code The authorisation code, {@code null} if not requested.
	 */
	public void setAuthorizationCode(final AuthorizationCode code) {
	
		this.code = code;
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
	 * Sets the requested UserInfo access token.
	 *
	 * @param accessToken The UserInfo access token, {@code null} if not 
	 *                    requested.
	 */
	public void setAccessToken(final AccessToken accessToken) {
	
		this.accessToken = accessToken;
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
	 * Sets the requested ID token.
	 *
	 * @param idToken The ID token (ready for output), {@code null} if not 
	 *                requested.
	 */
	public void setIDToken(final JWT idToken) {
	
		this.idToken = idToken;
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
	 * Sets the optional state, if requested to be echoed back to the 
	 * client.
	 *
	 * @param state The state, {@code null} if not requested.
	 */
	public void setState(final State state) {
	
		this.state = state;
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
					
				} catch (JWTException e) {
				
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
	 * @param url The URL to parse. May be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The parsed authorisation response.
	 *
	 * @throws ParseException If no valid authorisation response parameters
	 *                        are found in the URL.
	 */
	public static AuthorizationResponse parse(final URL url)
		throws ParseException {
		
		if (url == null)
			throw new NullPointerException("The URL must not be null");
		
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
		
		AuthorizationResponse response = new AuthorizationResponse(url);
		
		// Parse code parameter
		if (params.get("code") != null)
			response.setAuthorizationCode(new AuthorizationCode(params.get("code")));
		
		// Parse id_token parameter
		if (params.get("id_token") != null) {
		
			JWT idToken = null;
			
			try {
				idToken.parse(params.get("id_token"));
				
			} catch (JWTException e) {
			
				throw new ParseException("Invalid ID Token JWT: " + e.getMessage(), e);
			}
			
			response.setIDToken(idToken);
		}
		
		// Parse access_token parameters
		if (params.get("access_token") != null) {
		
			AccessToken accessToken = new AccessToken(params.get("access_token"));
			
			if (params.get("expires_in") != null) {
			
				long exp = -1;
			
				try {
					exp = new Long(params.get("expires_in"));
					
				} catch (NumberFormatException e) {
				
					throw new ParseException("Invalid expiration time: " + e.getMessage(), e);
				}
				
				accessToken.setExpiration(exp);
			}
			
			if (params.get("scope") != null) {
			
				try {
					accessToken.setScope(Scope.parseStrict(params.get("scope")));
					
				} catch (ParseException e) {
				
					throw new ParseException("Invalid UserInfo scope: " + e.getMessage(), e);
				}
			}
			
			response.setAccessToken(accessToken);
		}
		
		
		// Parse state parameter
		if (params.get("state") != null) {
		
			response.setState(new State(params.get("state")));
		}
		
		return response;
	}
}
