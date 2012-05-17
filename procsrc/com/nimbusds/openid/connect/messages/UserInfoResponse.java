package com.nimbusds.openid.connect.messages;


import javax.mail.internet.ContentType;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTException;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.claims.UserInfoClaims;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPResponse;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * UserInfo response.
 *
 * <p>The UserInfo claims may be passed as a plain JSON object or as a plain, 
 * signed or encrypted JSON Web Token (JWT). Use the appropriate constructor for
 * that.
 *
 * <p>Example JSON object representing a UserInfo response:
 *
 * <pre>
 * {
 *   "user_id"     : "248289761001",
 *   "name"        : "Jane Doe",
 *   "given_name"  : "Jane",
 *   "family_name" : "Doe",
 *   "email"       : "janedoe@example.com",
 *   "picture"     : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-17)
 */
public class UserInfoResponse implements SuccessResponse {


	/**
	 * The UserInfo claims, as plain JSON object.
	 */
	private UserInfoClaims claims;
	
	
	/**
	 * The UserInfo claims, as plain, signed or encrypted JWT.
	 */
	private JWT jwt;
	
	
	/**
	 * Creates a new UserInfo response where the claims are specified as
	 * plain JSON.
	 *
	 * @param claims The UserInfo claims. Must not be {@code null}.
	 */
	public UserInfoResponse(final UserInfoClaims claims) {
	
		if (claims == null)
			throw new NullPointerException("The claims must not be null");
		
		this.claims = claims;
	}
	
	
	/**
	 * Creates a new UserInfo response where the claims are specified as
	 * plain, signed or encrypted JSON Web Token (JWT).
	 *
	 * @param jwt The UserInfo claims. Must not be {@code null}.
	 */
	public UserInfoResponse(final JWT jwt) {
	
		if (jwt == null)
			throw new NullPointerException("The claims JWT must not be null");
		
		this.jwt = jwt;
	}
	
	
	/**
	 * Gets the content type of this UserInfo response.
	 *
	 * @return The content type, according to the claims format.
	 */
	public ContentType getContentType() {
	
		if (claims != null)
			return CommonContentTypes.APPLICATION_JSON;
		
		else
			return CommonContentTypes.APPLICATION_JWT;
		
	}
	
	
	/**
	 * Gets the UserInfo claims set.
	 *
	 * @return The UserInfo claims set, {@code null} if it was specified as
	 *         JSON Web Token (JWT) instead.
	 */
	public UserInfoClaims getUserInfoClaims() {
	
		return claims;
	}
	
	
	/**
	 * Gets the UserInfo claims set as JSON Web Token (JWT).
	 *
	 * @return The UserInfo claims set as a JSON Web Token (JWT), 
	 *         {@code null} if it was specified as a plain JSON object
	 *         instead.
	 */
	public JWT getUserInfoClaimsJWT() {
	
		return jwt;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		
		httpResponse.setContentType(getContentType());
		
		String content = null;
		
		if (claims != null) {
		
			content = claims.toJSONObject().toString();
		}
		else {
			try {
				content = jwt.serialize();
				
			} catch (JWTException e) {
			
				throw new SerializeException("Couldn't serialize UserInfo JWT claims: " + e.getMessage(), e);
			}
		}
		
		httpResponse.setContent(content);
	
		return httpResponse;
	}
	
	
	/**
	 * Parses a UserInfo response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The UserInfo response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        valid UserInfo response.
	 */
	public static UserInfoResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() != HTTPResponse.SC_OK)
			throw new ParseException("Unexpected HTTP status code, must be " + HTTPResponse.SC_OK);
		
		ContentType ct = httpResponse.getContentType();
		
		if (ct == null)
			throw new ParseException("Missing HTTP Content-Type header");
		
		String content = httpResponse.getContent();
		
		if (content == null)
			throw new ParseException("Missing HTTP response body");
		
		UserInfoResponse response = null;
		
		if (ct.match(CommonContentTypes.APPLICATION_JSON)) {
		
			JSONObject jsonObject = null;
			
			try {
				jsonObject = JSONObjectUtils.parseJSONObject(content);
				
			} catch (ParseException e) {
			
				throw new ParseException("Couldn't parse UserInfo claims JSON object: " + e.getMessage(), e);
			}
			
			UserInfoClaims claims = null;
			
			try {
				claims = UserInfoClaims.parse(jsonObject);
				
			} catch (ParseException e) {
				
				throw new ParseException("Couldn't parse UserInfo claims: " + e.getMessage(), e);
			}
			
			response = new UserInfoResponse(claims);
		}
		else if (ct.match(CommonContentTypes.APPLICATION_JWT)) {
		
			JWT jwt = null;
			
			try {
				jwt = JWT.parse(content);
				
			} catch (JWTException e) {
			
				throw new ParseException("Couldn't parse UserInfo claims JWT: " + e.getMessage(), e);
			}
			
			response = new UserInfoResponse(jwt);
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
