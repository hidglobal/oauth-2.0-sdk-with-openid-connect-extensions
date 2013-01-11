package com.nimbusds.openid.connect.sdk.messages;


import javax.mail.internet.ContentType;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.claims.sets.UserInfoClaims;

import com.nimbusds.openid.connect.sdk.http.CommonContentTypes;
import com.nimbusds.openid.connect.sdk.http.HTTPResponse;

import com.nimbusds.openid.connect.sdk.util.JSONObjectUtils;


/**
 * UserInfo response. This class is immutable.
 *
 * <p>The UserInfo claims may be passed as a plain JSON object or as a plain, 
 * signed or encrypted JSON Web Token (JWT). Use the appropriate constructor
 * for that.
 *
 * <p>Example JSON object representing a UserInfo response:
 *
 * <pre>
 * {
 *   "sub"                : "248289761001",
 *   "name"               : "Jane Doe",
 *   "given_name"         : "Jane",
 *   "family_name"        : "Doe",
 *   "preferred_username" : "j.doe",
 *   "email"              : "janedoe@example.com",
 *   "picture"            : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.4.2.
 *     <li>OpenID Connect Standard 1.0, section 4.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-13)
 */
@Immutable
public final class UserInfoResponse implements SuccessResponse {


	/**
	 * The UserInfo claims, as plain JSON object.
	 */
	private final UserInfoClaims claims;
	
	
	/**
	 * The UserInfo claims, as plain, signed or encrypted JWT.
	 */
	private final JWT jwt;
	
	
	/**
	 * Creates a new UserInfo response where the claims are specified in a
	 * plain JSON object.
	 *
	 * @param claims The UserInfo claims. Must not be {@code null}.
	 */
	public UserInfoResponse(final UserInfoClaims claims) {
	
		if (claims == null)
			throw new IllegalArgumentException("The claims must not be null");
		
		this.claims = claims;
		
		this.jwt = null;
	}
	
	
	/**
	 * Creates a new UserInfo response where the claims are specified as
	 * plain, signed or encrypted JSON Web Token (JWT).
	 *
	 * @param jwt The UserInfo claims. Must not be {@code null}.
	 */
	public UserInfoResponse(final JWT jwt) {
	
		if (jwt == null)
			throw new IllegalArgumentException("The claims JWT must not be null");
		
		this.jwt = jwt;
		
		this.claims = null;
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
	
	
	@Override
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
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The UserInfo response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        valid UserInfo response.
	 */
	public static UserInfoResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		
		httpResponse.ensureContentType();
		
		ContentType ct = httpResponse.getContentType();
		
		
		UserInfoResponse response = null;
		
		if (ct.match(CommonContentTypes.APPLICATION_JSON)) {
		
			UserInfoClaims claims = null;
			
			try {
				claims = UserInfoClaims.parse(httpResponse.getContentAsJSONObject());
				
			} catch (ParseException e) {
				
				throw new ParseException("Couldn't parse UserInfo claims: " + 
					                 e.getMessage(), e);
			}
			
			response = new UserInfoResponse(claims);
		}
		else if (ct.match(CommonContentTypes.APPLICATION_JWT)) {
		
			JWT jwt = null;
			
			try {
				jwt = httpResponse.getContentAsJWT();
				
			} catch (ParseException e) {
			
				throw new ParseException("Couldn't parse UserInfo claims JWT: " + 
					                 e.getMessage(), e);
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
