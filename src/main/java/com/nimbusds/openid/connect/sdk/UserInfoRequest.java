package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * UserInfo request. Used to retrieve the consented claims about the end-user. 
 * This class is immutable.
 *
 * <p>Example HTTP GET request:
 *
 * <pre>
 * GET /userinfo HTTP/1.1
 * Host: server.example.com
 * Authorization: Bearer SlAV32hkKG
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
public final class UserInfoRequest extends ProtectedResourceRequest {


	/**
	 * The HTTP method.
	 */
	private final HTTPRequest.Method httpMethod;
	
	
	/**
	 * Creates a new UserInfo HTTP GET request.
	 *
	 * @param uri         The URI of the UserInfo endpoint. May be
	 *                    {@code null} if the {@link #toHTTPRequest()}
	 *                    method will not be used.
	 * @param accessToken An OAuth 2.0 Bearer access token for the request.
	 *                    Must not be {@code null}.
	 */
	public UserInfoRequest(final URL uri, final BearerAccessToken accessToken) {
	
		this(uri, HTTPRequest.Method.GET, accessToken);
	}
	
	
	/**
	 * Creates a new UserInfo request.
	 *
	 * @param uri         The URI of the UserInfo endpoint. May be
	 *                    {@code null} if the {@link #toHTTPRequest()}
	 *                    method will not be used.
	 * @param httpMethod  The HTTP method. Must be HTTP GET or POST and not 
	 *                    {@code null}.
	 * @param accessToken An OAuth 2.0 Bearer access token for the request.
	 *                    Must not be {@code null}.
	 */
	public UserInfoRequest(final URL uri, final HTTPRequest.Method httpMethod, final BearerAccessToken accessToken) {
	
		super(uri, accessToken);
		
		if (httpMethod == null)
			throw new IllegalArgumentException("The HTTP method must not be null");
		
		this.httpMethod = httpMethod;
		
		
		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");
	}
	
	
	/**
	 * Gets the HTTP method for this UserInfo request.
	 *
	 * @return The HTTP method.
	 */
	public HTTPRequest.Method getMethod() {
	
		return httpMethod;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
		
		if (getURI() == null)
			throw new SerializeException("The endpoint URI is not specified");
	
		HTTPRequest httpRequest = new HTTPRequest(httpMethod, getURI());
		
		switch (httpMethod) {
		
			case GET:
				httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());	
				httpRequest.setQuery("schema=openid");
				break;
				
			case POST:
				httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
				httpRequest.setQuery("schema=openid" +
				                     "&access_token=" + getAccessToken().getValue());
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
		
		BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest);
	
		return new UserInfoRequest(httpRequest.getURL(), httpMethod, accessToken);
	}
}
