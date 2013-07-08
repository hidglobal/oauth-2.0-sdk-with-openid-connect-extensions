package com.nimbusds.openid.connect.sdk;


import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.Scope;


/**
 * Standard OpenID Connect scope value.
 * 
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.4.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCScopeValue extends Scope.Value {


	/**
	 * Informs the authorisation server that the client is making an OpenID 
	 * Connect request (REQUIRED). This scope values requests access to the
	 * {@code sub} claim. 
	 */
	public static final OIDCScopeValue OPENID =
		new OIDCScopeValue("openid", Scope.Value.Requirement.REQUIRED, new String[]{"sub"});
	
	
	/**
	 * Requests that access to the end-user's default profile claims at the 
	 * UserInfo endpoint be granted by the issued access token. These 
	 * claims are: {@code name}, {@code family_name}, {@code given_name}, 
	 * {@code middle_name}, {@code nickname}, {@code preferred_username}, 
	 * {@code profile}, {@code picture}, {@code website}, {@code gender}, 
	 * {@code birthdate}, {@code zoneinfo}, {@code locale}, and 
	 * {@code updated_at}. 
	 */
	public static final OIDCScopeValue PROFILE =
		new OIDCScopeValue("profile", new String[]{"name",
	                                                   "family_name",
	                                                   "given_name",
	                                                   "middle_name",
	                                                   "nickname",
	                                                   "preferred_username",
	                                                   "profile",
	                                                   "picture",
	                                                   "website",
	                                                   "gender",
	                                                   "birthdate",
	                                                   "zoneinfo",
	                                                   "locale",
	                                                   "updated_at"});
	
	
	/**
	 * Requests that access to the {@code email} and {@code email_verified}
	 * claims at the UserInfo endpoint be granted by the issued access 
	 * token.
	 */
	public static final OIDCScopeValue EMAIL =
		new OIDCScopeValue("email", new String[]{"email", "email_verified"});
	
	
	/**
	 * Requests that access to {@code address} claim at the UserInfo 
	 * endpoint be granted by the issued access token. 
	 */
	public static final OIDCScopeValue ADDRESS =
		new OIDCScopeValue("address", new String[]{"formatted",
	                                                   "street_address",
	                                                   "locality",
	                                                   "region",
	                                                   "postal_code",
	                                                   "country"});
	
	
	/**
	 * Requests that access to the {@code phone_number} and
	 * {@code phone_number_verified} claims at the UserInfo endpoint be 
	 * granted by the issued access token. 
	 */
	public static final OIDCScopeValue PHONE =
		new OIDCScopeValue("phone", new String[]{"phone_number",
		                                         "phone_number_verified"});


	/**
	 * Requests that an OAuth 2.0 refresh token be issued that can be used
	 * to obtain an access token that grants access the end-user's UserInfo
	 * endpoint even when the user is not present (not logged in).
	 */
	public static final OIDCScopeValue OFFLINE_ACCESS =
		new OIDCScopeValue("offline_access", null);


	/**
	 * The names of the associated claims, {@code null} if not applicable.
	 */
	private final Set<String> claims;


	/**
	 * Creates a new OpenID Connect scope token.
	 *
	 * @param value       The scope token value. Must not be {@code null}.
	 * @param requirement The requirement. Must not be {@code null}.
	 * @param claims      The names of the associated claims, {@code null} 
	 *                    if not applicable.
	 */
	private OIDCScopeValue(final String value, 
		               final Scope.Value.Requirement requirement,
	                       final String[] claims) {
	
		super(value, requirement);
		
		if (claims != null)
			this.claims = Collections.unmodifiableSet(new LinkedHashSet<String>(Arrays.asList(claims)));
		else
			this.claims = null;
	}


	/**
	 * Creates a new OpenID Connect scope token. The requirement is set to
	 * {@link ScopeValue.Requirement#OPTIONAL optional}.
	 *
	 * @param value  The scope token value. Must not be {@code null}.
	 * @param claims The names of the associated claims. Must not be
	 *               {@code null}.
	 */
	private OIDCScopeValue(final String value, 
		               final String[] claims) {
	
		this(value, Scope.Value.Requirement.OPTIONAL, claims);
	}


	/**
	 * Returns the names of the associated claims.
	 *
	 * @return The names of the associated claims, {@code null} if not
	 *         applicable.
	 */
	public Set<String> getClaims() {

		return claims;
	}
	
	
	/**
	 * Gets a default claims request JSON object for the scope token.
	 * 
	 * <p>See OpenID Connect Messages 1.0, section 2.6.1.
	 * 
	 * <p>Example JSON object for "openid" scope value:
	 * 
	 * <pre>
	 * {
	 *   "openid" : { "essential" : true }
	 * }
	 * </pre>
	 * 
	 * <p>Example JSON object for "email" scope value:
	 * 
	 * <pre>
	 * {
	 *   "email"          : null,
	 *   "email_verified" : null
	 * }
	 * </pre>
	 *
	 * @return The default claims request JSON object, {@code null} if not
	 *         applicable.
	 */
	public JSONObject getClaimsRequestJSONObject() {

		JSONObject req = new JSONObject();
		
		for (String claim: claims) {
		
			if (getRequirement() == Scope.Value.Requirement.REQUIRED) {
			
				// Essential (applies to OPENID - sub only)
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