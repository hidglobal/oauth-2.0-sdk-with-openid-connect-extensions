package com.nimbusds.openid.connect.sdk.messages;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;


/**
 * Enumeration of the standard {@link ScopeToken}s.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-10)
 */
public enum StdScopeToken implements ScopeToken {
	
	 
	/**
	 * Informs the authorisation server that the client is making an OpenID 
	 * Connect request (REQUIRED). This scope tokens requests access to 
	 * the {@code user_id} claim. 
	 */
	OPENID("openid", ScopeToken.Type.REQUIRED, new String[]{"user_id"}),
	
	
	/**
	 * Requests that access to the end-user's default profile claims at the 
	 * UserInfo endpoint be granted by the issued access token. These claims
	 * are: {@code name}, {@code family_name}, {@code given_name}, 
	 * {@code middle_name}, {@code nickname}, {@code preferred_username}, 
	 * {@code profile}, {@code picture}, {@code website}, {@code gender}, 
	 * {@code birthday}, {@code zoneinfo}, {@code locale}, and 
	 * {@code updated_time}. 
	 */
	PROFILE("profile", ScopeToken.Type.OPTIONAL, new String[]{"name",
	                                                          "family_name",
								  "given_name",
								  "middle_name",
								  "nickname",
								  "preferred_username",
								  "profile",
								  "picture",
								  "website",
								  "gender",
								  "birthday",
								  "zoneinfo",
								  "locale",
								  "updated_time"}),
	
	
	/**
	 * Requests that access to the {@code email} and {@code email_verified}
	 * claims at the UserInfo endpoint be granted by the issued access 
	 * token.
	 */
	EMAIL("email", ScopeToken.Type.OPTIONAL, new String[]{"email", "email_verified"}),
	
	
	/**
	 * Requests that access to {@code address} claim at the UserInfo 
	 * endpoint be granted by the issued access token. 
	 */
	ADDRESS("address", ScopeToken.Type.OPTIONAL, new String[]{"formatted",
	                                                          "street_address",
								  "locality",
								  "region",
								  "postal_code",
								  "country"}),
	
	
	/**
	 * Requests that access to the {@code phone_number} claim at the 
	 * UserInfo endpoint be granted by the issued access token. 
	 */
	PHONE("phone", ScopeToken.Type.OPTIONAL, new String[]{"phone_number"});


	/**
	 * The actual value.
	 */
	private final String value;
	
	
	/**
	 * The requirement type.
	 */
	private final ScopeToken.Type type;
	
	
	/**
	 * The names of the associated claims.
	 */
	private final Set<String> claims;
	
	
	/**
	 * Creates a new scope token.
	 *
	 * @param value  The scope token as a string. Must not be {@code null}.
	 * @param type   The requirement type. Must not be {@code null}.
	 * @param claims The names of the associated claims. Must not be
	 *               {@code null}.
	 */
	private StdScopeToken(final String value, 
	                      final ScopeToken.Type type,
			      final String[] claims) {
	
		this.value = value;
		this.type = type;
		
		this.claims = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(claims)));
	}
	
	
	@Override
	public String toString() {
	
		return value;
	}
	
	
	@Override
	public ScopeToken.Type getType() {
	
		return type;
	}
	
	
	@Override
	public Set<String> getClaims() {
	
		return claims;
	}
	
	
	@Override
	public JSONObject getClaimsRequestJSONObject() {
	
		JSONObject req = new JSONObject();
		
		for (String claim: claims) {
		
			if (type == ScopeToken.Type.REQUIRED) {
			
				// Essential (applies to OPENID - user_id only)
				JSONObject details = new JSONObject();
				details.put("essential", true);
				req.put(claim, details);
			}
			else {
				// Voluntary
				req.put(claim, null);
			}
		}
		
		return req;
	}
}
