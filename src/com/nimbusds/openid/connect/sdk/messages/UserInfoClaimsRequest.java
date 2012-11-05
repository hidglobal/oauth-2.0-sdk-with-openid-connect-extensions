package com.nimbusds.openid.connect.sdk.messages;


import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * Resolved UserInfo claims request. Specifies the claims to return at the
 * UserInfo endpoint. These are determined from the following:
 *
 * <ul>
 *     <li>The {@link Scope} passed with the {@code scope} parameter of the
 *         original {@link AuthorizationRequest}.
 *     <li>The optional OpenID Connect request object passed with the
 *         {@code request} or {@code request_uri} parameter of the original
 *         {@link AuthorizationRequest}.
 * </ul>
 *
 * <p>The final UserInfo claims request is determined by listing the
 * {@link #getClaimsObjectForScope default claims} for the specified UserInfo 
 * {@link Scope} and then merging the UserInfo claims from the optional OpenID 
 * Connect request object.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-05)
 */
public class UserInfoClaimsRequest extends ClaimsRequest {
	
	
	/**
	 * Optional array of requested locales, by order of preference.
	 */
	private LangTag[] preferredLocales;
	
	
	/**
	 * Gets the default claims request JSON object for the specified 
	 * UserInfo scope.
	 *
	 * @param scope The UserInfo scope. Must include an 
	 *              {@link ScopeToken#OPENID openid} scope token and must
	 *              not be {@code null}.
	 *
	 * @return The matching UserInfo claims request JSON object.
	 */
	public static JSONObject getClaimsObjectForScope(final Scope scope) {
	
		JSONObject claims = new JSONObject();
			
		if (scope.contains(ScopeToken.PROFILE))
			claims.putAll(ScopeToken.PROFILE.getClaimsRequestJSONObject());
		
		if (scope.contains(ScopeToken.EMAIL))
			claims.putAll(ScopeToken.EMAIL.getClaimsRequestJSONObject());
			
		if (scope.contains(ScopeToken.PHONE))
			claims.putAll(ScopeToken.PHONE.getClaimsRequestJSONObject());
		
		if (scope.contains(ScopeToken.ADDRESS)) {
			
			// Nested!
			JSONObject address = new JSONObject();
			address.put("address", ScopeToken.ADDRESS.getClaimsRequestJSONObject());
		
			claims.putAll(address);
		}
		
		return claims;
	}
	
	
	/**
	 * Parses a preferred locales array, by order of preference.
	 *
	 * @param object The JSON object to parse, any locales must be specified
	 *               as language tags (RFC 5646) in a JSON array named 
	 *               "preferred_locales".
	 *
	 * @return The preferred locales array, {@code null} if not specified.
	 *
	 * @throws LangTagException If an invalid language tag is encountered.
	 */
	private static LangTag[] parsePreferredLocales(final JSONObject object)
		throws LangTagException {
		
		LangTag[] preferredLocales = null;
		
		if (! object.containsKey("preferred_locales") ||
		    ! (object.get("preferred_locales") instanceof JSONArray)) {

			return null;
		}
				

		JSONArray locales = (JSONArray)object.get("preferred_locales");

		// Compose list of preferred locales   
		preferredLocales = new LangTag[locales.size()];

		for (int i=0; i < locales.size(); i++) {

			Object item = locales.get(i);

			if (! (item instanceof String))
				throw new LangTagException("Invalid language tag at position " + i);

			preferredLocales[i] = LangTag.parse((String)item);
		}
		
		return preferredLocales;
	}
	
	
	/**
	 * Creates a new resolved UserInfo claims request.
	 *
	 * @param scope          The UserInfo scope. Corresponds to the
	 *                       {@code scope} authorisation request parameter.
	 *                       Must not be {@code null}.
	 * @param userInfoObject The {@code userinfo} JSON object from the 
	 *                       optional OpenID request object. Obtained from 
	 *                       the decoded {@code request} or 
	 *                       {@code request_uri} authorisation request 
	 *                       parameter. {@code null} if not specified.
	 *
	 * @throws ResolveException If the ID Token claims request couldn't be
	 *                          resolved.
	 */
	public UserInfoClaimsRequest(final Scope scope, final JSONObject userInfoObject)
		throws ResolveException {
		
		// Set required claims
		requiredClaims.addAll(ScopeToken.OPENID.getClaims());
		
		
		// Resolve requested scope to claims
		requestedClaims.putAll(getClaimsObjectForScope(scope));
	
		// Request object with userinfo member present?
		if (userInfoObject != null) {
		
			if (userInfoObject.containsKey("claims") &&
		            userInfoObject.get("claims") instanceof JSONObject) {
		
				// Merge claims
				JSONObject additionalClaims = (JSONObject)userInfoObject.get("claims");

				requestedClaims.putAll(additionalClaims);
			}
			
			try {
				preferredLocales = parsePreferredLocales(userInfoObject);
				
			} catch (LangTagException e) {
			
				throw new ResolveException("Couldn't parse preferred locales: " + e.getMessage(), e);
			}
		}
	}
	
	
	/**
	 * Gets the preferred locales.
	 *
	 * @return The preferred locales, by order of preference, {@code null}
	 *         if none.
	 */
	public LangTag[] getPreferredLocales() {
	
		return preferredLocales;
	}
}
