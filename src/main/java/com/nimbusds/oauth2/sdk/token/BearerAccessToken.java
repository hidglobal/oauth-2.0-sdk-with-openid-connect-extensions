package com.nimbusds.oauth2.sdk.token;


import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import java.util.Map;


/**
 * Bearer access token. This class is immutable.
 *
 * <p>Example bearer access token serialised to JSON:
 *
 * <pre>
 * {
 *   "access_token" : "2YotnFZFEjr1zCsicMWpAA",
 *   "token_type"   : "bearer",
 *   "expires_in"   : 3600,
 *   "scope"        : "read write"
 * }
 * </pre>
 *
 * <p>The above example token serialised to a HTTP Authorization header:
 *
 * <pre>
 * Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 5.1.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750).
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class BearerAccessToken extends AccessToken {

	
	/**
	 * Creates a new minimal bearer access token with a randomly generated 
	 * 256-bit (32-byte) value, Base64URL-encoded. The optional lifetime 
	 * and scope are left undefined.
	 */
	public BearerAccessToken() {
	
		this(32);
	}	


	/**
	 * Creates a new minimal bearer access token with a randomly generated 
	 * value of the specified byte length, Base64URL-encoded. The optional 
	 * lifetime and scope are left undefined.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public BearerAccessToken(final int byteLength) {
	
		this(byteLength, 0l, null);
	}


	/**
	 * Creates a new bearer access token with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 *
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public BearerAccessToken(final long lifetime, final Scope scope) {
	
		this(32, lifetime, scope);
	}


	/**
	 * Creates a new bearer access token with a randomly generated value of 
	 * the specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 * @param lifetime   The lifetime in seconds, 0 if not specified.
	 * @param scope      The scope, {@code null} if not specified.
	 */
	public BearerAccessToken(final int byteLength, final long lifetime, final Scope scope) {
	
		super(AccessTokenType.BEARER, byteLength, lifetime, scope);
	}
	
	
	/**
	 * Creates a new minimal bearer access token with the specified value.
	 * The optional lifetime and scope are left undefined.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 */
	public BearerAccessToken(final String value) {
	
		this(value, 0l, null);
	}
	
	
	/**
	 * Creates a new bearer access token with the specified value and 
	 * optional lifetime and scope.
	 *
	 * @param value    The access token value. Must not be {@code null} or
	 *                 empty string.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public BearerAccessToken(final String value, final long lifetime, final Scope scope) {
	
		super(AccessTokenType.BEARER, value, lifetime, scope);
	}
	
	
	/**
	 * Returns the HTTP Authorization header value for this bearer access 
	 * token.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9
	 * </pre>
	 *
	 * @return The HTTP Authorization header.
	 */
	@Override
	public String toAuthorizationHeader(){
	
		return "Bearer " + getValue();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof BearerAccessToken && 
		       this.toString().equals(object.toString());
	}


	/**
	 * Parses a bearer access token from a JSON object access token 
	 * response.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The bearer access token.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        bearer access token.
	 */
	public static BearerAccessToken parse(final JSONObject jsonObject)
		throws ParseException {

		// Parse and verify type
		AccessTokenType tokenType = new AccessTokenType(JSONObjectUtils.getString(jsonObject, "token_type"));
		
		if (! tokenType.equals(AccessTokenType.BEARER))
			throw new ParseException("Token type must be \"Bearer\"");
		

		// Parse value
		String accessTokenValue = JSONObjectUtils.getString(jsonObject, "access_token");
		

		// Parse lifetime
		long lifetime = 0;
		
		if (jsonObject.containsKey("expires_in")) {

			// Lifetime can be a JSON number or string

			if (jsonObject.get("expires_in") instanceof Number) {

				lifetime = JSONObjectUtils.getLong(jsonObject, "expires_in");
			}
			else {
				String lifetimeStr = JSONObjectUtils.getString(jsonObject, "expires_in");

				try {
					lifetime = new Long(lifetimeStr);

				} catch (NumberFormatException e) {

					throw new ParseException("Invalid \"expires_in\" parameter, must be integer");
				}
			}
		}


		// Parse scope
		Scope scope = null;

		if (jsonObject.containsKey("scope"))
			scope = Scope.parse(JSONObjectUtils.getString(jsonObject, "scope"));


		return new BearerAccessToken(accessTokenValue, lifetime, scope);
	}
	
	
	/**
	 * Parses an HTTP Authorization header for a bearer access token.
	 *
	 * @param header The HTTP Authorization header value to parse. Must not
	 *               be {@code null}.
	 *
	 * @return The bearer access token.
	 *
	 * @throws ParseException If the HTTP Authorization header value 
	 *                        couldn't be parsed to a bearer access token.
	 */
	public static BearerAccessToken parse(final String header)
		throws ParseException {
	
		String[] parts = header.split("\\s", 2);
	
		if (parts.length != 2)
			throw new ParseException("Invalid HTTP Authorization header value");
		
		if (! parts[0].equals("Bearer"))
			throw new ParseException("Token type must be \"Bearer\"");
		
		try {
			return new BearerAccessToken(parts[1]);
			
		} catch (IllegalArgumentException e) {
		
			throw new ParseException(e.getMessage());
		}
	}
	
	
	/**
	 * Parses an HTTP request for a bearer access token.
	 * 
	 * @param request The HTTP request to parse. Must be GET or POST, and
	 *                not {@code null}.
	 * 
	 * @return The bearer access token.
	 * 
	 * @throws ParseException If a bearer access token wasn't found in the
	 *                        HTTP request.
	 */
	public static BearerAccessToken parse(final HTTPRequest request)
		throws ParseException {
		
		if (request.getMethod().equals(HTTPRequest.Method.GET)) {
			
			String authzHeader = request.getAuthorization();
				
			if (authzHeader != null) {
				
				return parse(authzHeader);
			}
			
			Map<String,String> params = request.getQueryParameters();	
			
			if (params.get("access_token") != null) {
				
				return parse(params.get("access_token"));
			}
			
			throw new ParseException("Missing Bearer access token");
			
		} else if (request.getMethod().equals(HTTPRequest.Method.POST)) {
			
			Map<String,String> params = request.getQueryParameters();	
			
			if (params.get("access_token") != null) {
				
				return parse(params.get("access_token"));
			}
			
			throw new ParseException("Missing Bearer access token");
			
		} else {
			throw new ParseException("Unexpected HTTP method: " + request.getMethod());
		}
	}
}
