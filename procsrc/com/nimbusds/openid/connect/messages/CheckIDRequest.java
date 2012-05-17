package com.nimbusds.openid.connect.messages;


import java.net.URLEncoder;
import java.util.Map;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTException;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.HTTPRequest;
import com.nimbusds.openid.connect.http.CommonContentTypes;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Check ID request. To request the defails of the authentication performed on 
 * the end-user, a request is made to the Check ID Endpoint sending the ID Token
 * as the {@code access_token} by using the OAuth 2.0 Bearer scheme. 
 *
 * <p>The request can be constructed from a JSON Web Token (JWT) object or an 
 * opaque string representing the ID Token to check.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /check_id HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * 
 * access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC
 * 9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiaH
 * R0cDpcL1wvY2xpZW50LmV4YW1wbGUuY29tIiwiZXhwIjoxMzExMjgxOTcwfQ.eDesUD0vzDH
 * 3T1G3liaTNOrfaeWYjuRCEPNXVtaazNQ
 * </pre>
 *
 * <p>See http://openid.net/specs/openid-connect-standard-1_0.html#anchor15
 * <p>See http://openid.net/specs/openid-connect-messages-1_0.html#anchor10
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-13)
 */
public class CheckIDRequest implements Request {
	
	 
	/**
	 * The ID Token as an opaque access token.
	 */
	private AccessToken accessToken = null;
	
	
	/**
	 * The ID Token as JSON Web Token (JWT).
	 */
	private JWT jwt = null;
	
	
	/**
	 * Creates a new check ID request with the specified opaque string as 
	 * the access token.
	 *
	 * @param accessToken The access token, which should parse to a valid 
	 *                    JWT. Must not be {@code null}.
	 */
	public CheckIDRequest(final AccessToken accessToken) {
	
		if (accessToken == null)
			throw new NullPointerException("The access token must not be null");
	
		this.accessToken = accessToken;
	}
	
	
	/**
	 * Creates a new check ID request with the specified JSON Web Token 
	 * (JWT) as the access token.
	 *
	 * @param jwt The access token, which must be a valid JWT. Must not be
	 *            {@code null}.
	 */
	public CheckIDRequest(final JWT jwt) {
	
		if (jwt == null)
			throw new NullPointerException("The JWT must not be null");
	
		this.jwt = jwt;
	}
	
	
	/**
	 * Gets the access token as an opaque string.
	 *
	 * @return The access token.
	 *
	 * @throws JWTException If the access token was specified as a JWT which 
	 *                      is in a state doesn't permit serialisation (e.g. 
	 *                      unsigned or enencrypted).
	 */
	public AccessToken getAccessToken()
		throws JWTException {
	
		if (accessToken != null)
			return accessToken;
		else
			return new AccessToken(jwt.serialize());
	}
	
	
	/**
	 * Gets the access token as a JSON Web Token (JWT).
	 *
	 * @return The access token.
	 *
	 * @throws JWTException If the access token was specified as an opaque
	 *                      string which cannot be parsed to a JSON Web 
	 *                      Token (JWT).
	 */
	public JWT getJWT()
		throws JWTException {

		if (jwt != null)
			return jwt;
		else
			return JWT.parse(accessToken.getValue());
	}
	
	
	/**
	 * Returns the HTTP request for this check ID request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If this check ID request couldn't be 
	 *                            serialised to an HTTP request.
	 */
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		StringBuilder sb = new StringBuilder("access_token=");
		
		if (accessToken != null) {
			sb.append(accessToken.getValue());
		}
		else {
			try {
				sb.append(jwt.serialize());
				
			} catch (JWTException e) {
			
				throw new SerializeException("Couldn't serialize check ID request: " + e.getMessage(), e);
			}
		}
	
		httpRequest.setQuery(sb.toString());
	
		return httpRequest;
	}
	
	
	/**
	 * Parses a check ID request from the specified HTTP request. The access
	 * token is not checked for being a valid JSON Web Token (JWT).
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The parsed check ID request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        valid check ID request.
	 */
	public static CheckIDRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		if (httpRequest.getContentType() != null &&
		    ! httpRequest.getContentType().equals(CommonContentTypes.APPLICATION_URLENCODED))
			throw new ParseException("The Content-Type header must be application/x-www-form-urlencoded");
		
		String query = httpRequest.getQuery();
		
		if (query == null || query.isEmpty())
			throw new ParseException("Missing HTTP POST body");
		
		Map<String,String> params = URLUtils.parseParameters(query);
		
		String jwtString = params.get("access_token");
		
		if (jwtString == null || jwtString.isEmpty())
			throw new ParseException("Missing access_token form parameter");
		
		return new CheckIDRequest(new AccessToken(jwtString));
	}
}
