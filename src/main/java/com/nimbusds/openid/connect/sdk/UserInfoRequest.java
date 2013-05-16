package com.nimbusds.openid.connect.sdk;


import java.net.URL;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Request;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;


/**
 * UserInfo request. Used to retrieve requested claims about the end-user. This
 * class is immutable.
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
 * schema=openid&amp;access_token=mF_9.B5f-4.1JqM
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.3.1.
 *     <li>OpenID Connect Standard 1.0, section 4.1.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC6750), section 2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class UserInfoRequest implements Request {


	/**
	 * The HTTP method.
	 */
	private final HTTPRequest.Method httpMethod;
	 
	 
	/**
	 * The UserInfo access token.
	 */
	private final AccessToken accessToken;
	
	
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
	 * @param httpMethod  The HTTP method. Must be HTTP GET or POST and not 
	 *                    {@code null}.
	 * @param accessToken The UserInfo access token. Must not be
	 *                    {@code null}.
	 */
	public UserInfoRequest(final HTTPRequest.Method httpMethod, final AccessToken accessToken) {
	
		if (httpMethod == null)
			throw new IllegalArgumentException("The HTTP method must not be null");
		
		this.httpMethod = httpMethod;
		
		
		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");
		
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
	
	
	@Override
	public HTTPRequest toHTTPRequest(final URL url)
		throws SerializeException {
	
		HTTPRequest httpRequest = new HTTPRequest(httpMethod, url);
		
		switch (httpMethod) {
		
			case GET:
				httpRequest.setAuthorization(accessToken.toAuthorizationHeader());	
				httpRequest.setQuery("schema=openid");
				break;
				
			case POST:
				httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
				httpRequest.setQuery("schema=openid" +
				                     "&access_token=" + accessToken.getValue());
				break;
			
			default:
				throw new SerializeException("Unexpected HTTP method: " + httpMethod);
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
	 *                        UserInfo request.
	 */
	public static UserInfoRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		HTTPRequest.Method httpMethod = httpRequest.getMethod();
		
		AccessToken accessToken = null;
		
		switch (httpMethod) {
		
			case GET:
			
				String authzHeader = httpRequest.getAuthorization();
				
				if (authzHeader == null)
					throw new ParseException("Missing HTTP Authorization header");
				
				accessToken = AccessToken.parse(authzHeader);
				
				String query = httpRequest.getQuery();
				
				if (query == null)
					throw new ParseException("Missing query string");
				
				if (query.indexOf("schema=openid") < 0)
					throw new ParseException("Missing or unexpected schema parameter, must be \"openid\"");
				
				break;
				
				
			case POST:
			
				httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
				
				Map<String,String> params = httpRequest.getQueryParameters();	
			
				if (! params.containsKey("schema"))
					throw new ParseException("Missing schema parameter");
				
				if ("openid".equals(params.get("schema")))
					throw new ParseException("Unexpected schema parameter, must be \"openid\"");
			
				if (! params.containsKey("access_token"))
					throw new ParseException("Missing access_token parameter");
				
				accessToken = AccessToken.parse(params.get("access_token"));
			
				break;
			
			default:
				throw new ParseException("Unexpected HTTP method: " + httpMethod);
		}
	
		return new UserInfoRequest(httpMethod, accessToken);
	}
}
