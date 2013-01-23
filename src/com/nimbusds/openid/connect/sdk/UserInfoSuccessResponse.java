package com.nimbusds.openid.connect.sdk;


import javax.mail.internet.ContentType;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;

import com.nimbusds.oauth2.sdk.OAuth2SuccessResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;


/**
 * UserInfo success response. This class is immutable.
 *
 * <p>The UserInfo claims may be passed as an unprotected JSON object or as a 
 * plain, signed or encrypted JSON Web Token (JWT). Use the appropriate 
 * constructor for that.
 *
 * <p>Example UserInfo HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * 
 * {
 *  "sub"         : "248289761001",
 *  "name"        : "Jane Doe"
 *  "given_name"  : "Jane",
 *  "family_name" : "Doe",
 *  "email"       : "janedoe@example.com",
 *  "picture"     : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.3.2.
 *     <li>OpenID Connect Standard 1.0, section 4.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-23)
 */
@Immutable
public final class UserInfoSuccessResponse implements OAuth2SuccessResponse {


	/**
	 * The UserInfo claims set, serialisable to a JSON object.
	 */
	private final UserInfo claimsSet;
	
	
	/**
	 * The UserInfo claims set, as plain, signed or encrypted JWT.
	 */
	private final JWT jwt;
	
	
	/**
	 * Creates a new UserInfo success response where the claims are 
	 * specified as an unprotected UserInfo claims set.
	 *
	 * @param claimsSet The UserInfo claims set. Must not be {@code null}.
	 */
	public UserInfoSuccessResponse(final UserInfo claimsSet) {
	
		if (claimsSet == null)
			throw new IllegalArgumentException("The claims must not be null");
		
		this.claimsSet = claimsSet;
		
		this.jwt = null;
	}
	
	
	/**
	 * Creates a new UserInfo success response where the claims are 
	 * specified as a plain, signed or encrypted JSON Web Token (JWT).
	 *
	 * @param jwt The UserInfo claims set. Must not be {@code null}.
	 */
	public UserInfoSuccessResponse(final JWT jwt) {
	
		if (jwt == null)
			throw new IllegalArgumentException("The claims JWT must not be null");
		
		this.jwt = jwt;
		
		this.claimsSet = null;
	}
	
	
	/**
	 * Gets the content type of this UserInfo response.
	 *
	 * @return The content type, according to the claims format.
	 */
	public ContentType getContentType() {
	
		if (claimsSet != null)
			return CommonContentTypes.APPLICATION_JSON;
		else
			return CommonContentTypes.APPLICATION_JWT;
		
	}
	
	
	/**
	 * Gets the UserInfo claims set as an unprotected UserInfo claims set.
	 *
	 * @return The UserInfo claims set, {@code null} if it was specified as
	 *         JSON Web Token (JWT) instead.
	 */
	public UserInfo getUserInfo() {
	
		return claimsSet;
	}
	
	
	/**
	 * Gets the UserInfo claims set as a plain, signed or encrypted JSON
	 * Web Token (JWT).
	 *
	 * @return The UserInfo claims set as a JSON Web Token (JWT), 
	 *         {@code null} if it was specified as an unprotected UserInfo
	 *         claims set instead.
	 */
	public JWT getUserInfoJWT() {
	
		return jwt;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		
		httpResponse.setContentType(getContentType());
		
		String content = null;
		
		if (claimsSet != null) {
		
			content = claimsSet.getJSONObject().toString();
		}
		else {
			try {
				content = jwt.serialize();
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize UserInfo claims JWT: " + 
					                     e.getMessage(), e);
			}
		}
		
		httpResponse.setContent(content);
	
		return httpResponse;
	}
	
	
	/**
	 * Parses a UserInfo response from the specified HTTP response.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 200 OK
	 * Content-Type: application/json
	 * 
	 * {
	 *  "sub"         : "248289761001",
	 *  "name"        : "Jane Doe"
	 *  "given_name"  : "Jane",
	 *  "family_name" : "Doe",
	 *  "email"       : "janedoe@example.com",
	 *  "picture"     : "http://example.com/janedoe/me.jpg"
	 * }
	 * </pre>
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The UserInfo response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        UserInfo response.
	 */
	public static UserInfoSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		
		httpResponse.ensureContentType();
		
		ContentType ct = httpResponse.getContentType();
		
		
		UserInfoSuccessResponse response = null;
		
		if (ct.match(CommonContentTypes.APPLICATION_JSON)) {
		
			UserInfo claimsSet = null;
			
			try {
				claimsSet = new UserInfo(httpResponse.getContentAsJSONObject());
				
			} catch (Exception e) {
				
				throw new ParseException("Couldn't parse UserInfo claims: " + 
					                 e.getMessage(), e);
			}
			
			response = new UserInfoSuccessResponse(claimsSet);
		}
		else if (ct.match(CommonContentTypes.APPLICATION_JWT)) {
		
			JWT jwt = null;
			
			try {
				jwt = httpResponse.getContentAsJWT();
				
			} catch (ParseException e) {
			
				throw new ParseException("Couldn't parse UserInfo claims JWT: " + 
					                 e.getMessage(), e);
			}
			
			response = new UserInfoSuccessResponse(jwt);
		}
		else {
			throw new ParseException("Unexpected Content-Type, must be " + 
			                         CommonContentTypes.APPLICATION_JSON +
						 " or " +
						 CommonContentTypes.APPLICATION_JWT);
		}
		
		return response;
	}
}
