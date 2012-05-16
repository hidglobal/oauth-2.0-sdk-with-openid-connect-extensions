package com.nimbusds.openid.connect.messages;


import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTagException;


/**
 * The resolved UserInfo claims request. It is determined by listing the default
 * claims for the specified UserInfo {@link Scope} and then merging the UserInfo 
 * claims from the optional {@link AuthorizationRequest#getResolvedRequestObject
 * OpenID request object}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-23)
 */
public class ResolvedUserInfoClaimsRequest extends ClaimsRequest {
	
	
	/**
	 * Gets the default UserInfo claims request for the
	 * {@link StdScopeMember#OPENID openid scope}.
	 *
	 * @return The UserInfo openid scope request.
	 */
	public static JSONObject getClaimsRequestForOpenIDScope() {
	
		JSONObject openidClaims = new JSONObject();
		openidClaims.put("user_id", null);
		return openidClaims;
	}
	
	
	/**
	 * Gets the default UserInfo claims request for the
	 * {@link StdScopeMember#PROFILE profile scope}.
	 *
	 * @return The UserInfo profile scope request.
	 */
	public static JSONObject getClaimsRequestForProfileScope() {
	
		JSONObject profileClaims = new JSONObject();
			
		JSONObject opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("name", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("family_name", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("given_name", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("middle_name", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("nickname", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("profile", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("picture", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("website", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("gender", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("birthday", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("locale", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("zoneinfo", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("locale", opt);

		opt = new JSONObject();
		opt.put("optional", true);
		profileClaims.put("updated_time", opt);
		
		return profileClaims;
	}
	
	
	/**
	 * Gets the default UserInfo claims request for the
	 * {@link StdScopeMember#EMAIL email scope}.
	 *
	 * @return The UserInfo email scope request.
	 */
	public static JSONObject getClaimsRequestForEmailScope() {
	
		JSONObject emailClaims = new JSONObject();
		
		JSONObject opt = new JSONObject();
		opt.put("optional", true);
		emailClaims.put("email", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		emailClaims.put("verified", opt);
		
		return emailClaims;
	}
	
	
	/**
	 * Gets the default UserInfo claims request for the
	 * {@link StdScopeMember#ADDRESS address scope}.
	 *
	 * @return The UserInfo address scope request.
	 */
	public static JSONObject getClaimsRequestForAddressScope() {
	
		JSONObject addressClaims = new JSONObject();
		
		// Uses sub-object
		JSONObject address = new JSONObject();
		
		JSONObject opt = new JSONObject();
		opt.put("optional", true);
		address.put("formatted", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		address.put("street_address", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		address.put("locality", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		address.put("region", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		address.put("postal_code", opt);
		
		opt = new JSONObject();
		opt.put("optional", true);
		address.put("country", opt);
		
		
		addressClaims.put("address", address);
		return addressClaims;
	}
	
	
	/**
	 * Gets the default UserInfo claims request for the
	 * {@link StdScopeMember#PHONE phone scope}.
	 *
	 * @return The UserInfo phone scope request.
	 */
	public static JSONObject getClaimsRequestForPhoneScope() {
	
		JSONObject phoneClaims = new JSONObject();
		
		JSONObject opt = new JSONObject();
		opt.put("optional", true);
		phoneClaims.put("phone_number", opt);
		
		return phoneClaims;
	}
	
	
	/**
	 * Gets the default claims for the specified UserInfo scope.
	 *
	 * @param scope The UserInfo scope. Must not be {@code null}.
	 *
	 * @return The matching UserInfo claims request.
	 */
	public static JSONObject getClaimsForScope(final Scope scope) {
	
		JSONObject claims = new JSONObject();
		
		if (scope.contains(StdScopeMember.OPENID))
			claims.putAll(getClaimsRequestForOpenIDScope());
			
		if (scope.contains(StdScopeMember.PROFILE))
			claims.putAll(getClaimsRequestForProfileScope());
		
		if (scope.contains(StdScopeMember.EMAIL))
			claims.putAll(getClaimsRequestForEmailScope());
			
		if (scope.contains(StdScopeMember.PHONE))
			claims.putAll(getClaimsRequestForPhoneScope());
		
		if (scope.contains(StdScopeMember.ADDRESS))
			claims.putAll(getClaimsRequestForAddressScope());
		
		return claims;
	}
	
	
	/**
	 * Creates a new resolved UserInfo claims request.
	 *
	 * @param scope          The UserInfo scope. Must not be {@code null}.
	 * @param userInfoObject The UserInfo object from the optional OpenID
	 *                       request object. {@code null} if not specified.
	 *
	 * @throws ResolveException If the ID Token claims request couldn't be
	 *                          resolved.
	 */
	public ResolvedUserInfoClaimsRequest(final Scope scope, final JSONObject userInfoObject)
		throws ResolveException {
		
		// Resolve scope to claims
		claims.putAll(getClaimsForScope(scope));
	
		if (userInfoObject != null) {
		
			if (userInfoObject.containsKey("claims") &&
		            userInfoObject.get("claims") instanceof JSONObject) {
		
				// Merge claims
				JSONObject additionalClaims = (JSONObject)userInfoObject.get("claims");

				claims.putAll(additionalClaims);
			}
			
			try {
				preferredLocales = ClaimsRequest.parsePreferredLocales(userInfoObject);
				
			} catch (LangTagException e) {
			
				throw new ResolveException("Couldn't parse preferred locales: " + e.getMessage(), e);
			}
		}
	}
}
