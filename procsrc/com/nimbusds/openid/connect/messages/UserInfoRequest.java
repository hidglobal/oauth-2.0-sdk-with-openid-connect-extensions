package com.nimbusds.openid.connect.messages;


import java.util.Map;

import javax.mail.internet.ContentType;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPRequest;


/**
 * UserInfo request.
 *
 * <p>Example HTTP GET request:
 *
 * <pre>
 * GET /userinfo?schema=openid HTTP/1.1
 * Host: server.example.com
 * Authorization: Bearer mF_9.B5f-4.1JqM
 * </pre>
 *
 * <p>Example HTTP POST request:
 *
 * <pre>
 * POST /userinfo HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * schema=openid&access_token=mF_9.B5f-4.1JqM
 * </pre>
 *
 * <p>See draft-ietf-oauth-v2-bearer-19, section 2.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-17)
 */
public class UserInfoRequest implements Request {


	/**
	 * The HTTP method.
	 */
	private HTTPRequest.Method httpMethod;
	 
	 
	/**
	 * The UserInfo access token.
	 */
	private AccessToken accessToken;
	
	
	/**
	 * Creates a new UserInfo HTTP GET request.
	 *
	 * @param accessToken The UserInfo access token. Must not be 
	 *                    {@code null}.
	 */
	public UserInfoRequest(final AccessToken accessToken) {
	
		this(HTTPRequest.Method.GET, accessToken);
	}
	
	
	/**
	 * Creates a new UserInfo request.
	 *
	 * @param httpMethod  The HTTP method. Must not be {@code null}.
	 * @param accessToken The UserInfo access token. Must not be
	 *                    {@code null}.
	 */
	public UserInfoRequest(final HTTPRequest.Method httpMethod, final AccessToken accessToken) {
	
		if (httpMethod == null)
			throw new NullPointerException("The HTTP method must not be null");
		
		this.httpMethod = httpMethod;
		
		
		if (accessToken == null)
			throw new NullPointerException("The access token must not be null");
		
		this.accessToken = accessToken;
	}
	
	
	/**
	 * Gets the HTTP method for this UserInfo request.
	 *
	 * @return The HTTP method.
	 */
	public HTTPRequest.Method getMethod() {
	
		return httpMethod;
	}
	
	
	/**
	 * Gets the UserInfo access token.
	 *
	 * @return The UserInfo access token.
	 */
	public AccessToken getAccessToken() {
	
		return accessToken;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
	
		HTTPRequest httpRequest = new HTTPRequest(httpMethod);
		
		switch (httpMethod) {
		
			case GET:
				httpRequest.setAuthorization(accessToken.toAuthorizationHeader());	
				httpRequest.setQuery("?schema=openid");
				break;
				
			case POST:
				httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
				httpRequest.setQuery("?schema=openid" +
				                     "&access_token=" + accessToken.getValue());
				break;
			
			default:
				throw new SerializeException("Couldn't serialize UserInfo request: Unexpected HTTP method: " + httpMethod);
		}
		
		return httpRequest;
	}
	
	
	/**
	 * Parses the specified HTTP request for a UserInfo request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The UserInfo request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        valid UserInfo request.
	 */
	public static UserInfoRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		HTTPRequest.Method httpMethod = httpRequest.getMethod();
		
		AccessToken accessToken = null;
		
		switch (httpMethod) {
		
			case GET:
			
				String authzHeader = httpRequest.getAuthorization();
				
				if (authzHeader == null)
					throw new ParseException("Couldn't parse UserInfo request: Missing HTTP Authorization header");
				
				accessToken = AccessToken.parse(authzHeader);
				
				String query = httpRequest.getQuery();
				
				if (query == null)
					throw new ParseException("Couldn't parse UserInfo request: Missing query string");
				
				if (query.indexOf("schema=openid") < 0)
					throw new ParseException("Couldn't parse UserInfo request: Missing or unexpected schema parameter, must be \"openid\"");
				
				break;
				
				
			case POST:
			
				httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
				
				Map<String,String> params = httpRequest.getQueryParameters();	
			
				if (! params.containsKey("schema"))
					throw new ParseException("Couldn't parse UserInfo request: Missing schema parameter");
				
				if ("openid".equals(params.get("schema")))
					throw new ParseException("Couldn't parse UserInfo request: Unexpected schema parameter, must be \"openid\"");
			
				if (! params.containsKey("access_token"))
					throw new ParseException("Couldn't parse UserInfo request: Missing access_token parameter");
				
				accessToken = new AccessToken(params.get("access_token"));
			
				break;
			
			default:
				throw new ParseException("Couldn't parse UserInfo request: Unexpected HTTP method: " + httpMethod);
		}
	
		return new UserInfoRequest(httpMethod, accessToken);
	}
}
