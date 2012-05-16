package com.nimbusds.openid.connect.messages;


import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTException;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * Access token response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 * 
 * {
 *   "access_token"  : "SlAV32hkKG",
 *   "token_type"    : "Bearer",
 *   "refresh_token" : "8xLOxBtZp8",
 *   "expires_in"    : 3600,
 *   "id_token"      : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOl
 * wvXC9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIj
 * oiaHR0cDpcL1wvY2xpZW50LmV4YW1wbGUuY29tIiwiZXhwIjoxMzExMjgxOTcwfQ.eDesUD0
 * vzDH3T1G3liaTNOrfaeWYjuRCEPNXVtaazNQ"
 * }
 * </pre>
 *
 * <p>See draft-ietf-oauth-v2-26, section 4.1.4.
 *
 * <p>See draft-ietf-oauth-v2-26, section 5.1.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-13)
 */
public class AccessTokenResponse implements SuccessResponse {


	/**
	 * The access token.
	 */
	private AccessToken accessToken;
	
	
	/**
	 * Optional ID Token serialised to a JWT.
	 */
	private JWT idToken = null;
	
	
	/**
	 * Optional refresh token.
	 */
	private RefreshToken refreshToken = null;
	
	
	/**
	 * Creates a new access token response.
	 *
	 * <p>Rules:
	 *
	 * <ul>
	 *     <li>
	 *     <li>
	 * </ul>
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param idToken      The ID token. Must not be {@code null} if a 
	 *                     refresh token is not specified. Must be 
	 *                     {@code null} if a refresh token is specified.
	 * @param refreshToken Optional refresh token, {@code null} if none.
	 *
	 * @throws IllegalArgumentException If an ID token and a refresh token
	 *                                  are specified at the same time.
	 */
	public AccessTokenResponse(final AccessToken accessToken,
	                           final JWT idToken,
	                           final RefreshToken refreshToken) {
				   
		if (accessToken == null)
			throw new NullPointerException("The access token must not be null");
		
		this.accessToken = accessToken;
		
		if (idToken != null && refreshToken != null)
			throw new IllegalArgumentException("An ID token and a refresh token cannot be specified at the same time");
		
		if (idToken == null && refreshToken == null)
			throw new IllegalArgumentException("Missing ID token");
			
		this.idToken = idToken;
		this.refreshToken = refreshToken;
	}
	
	
	/**
	 * Gets the access token.
	 *
	 * @return The access token.
	 */
	public AccessToken getAccessToken() {
	
		return accessToken;
	}
	
	
	/**
	 * Gets the optional refresh token.
	 *
	 * @return The refresh token, {@code null} if none.
	 */
	public RefreshToken getRefreshToken() {
	
		return refreshToken;
	}
	
	
	/**
	 * Returns the JSON object representing this access token response.
	 *
	 * @return The JSON object.
	 *
	 * @throws SerializeException If this access token response couldn't be
	 *                            serialised to a JSON object.
	 */
	public JSONObject toJSONObject()
		throws SerializeException {
	
		JSONObject o = new JSONObject();
		
		o.put("access_token", accessToken.getValue());
		o.put("token_type", AccessToken.TYPE);
		
		if (accessToken.getExpiration() > 0)
			o.put("expires_in", accessToken.getExpiration());
		
		try {
			o.put("id_token", idToken.serialize());
			
		} catch (JWTException e) {
		
			throw new SerializeException("Couldn't serialize ID token: " + e.getMessage(), e);
		}
		
		if (refreshToken != null)
			o.put("refresh_token", refreshToken.getValue());
		
		return o;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		
		httpResponse.setContent(toJSONObject().toString());
		
		return httpResponse;
	}
	
	
	public static AccessTokenResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		
		return null;
	}
}
