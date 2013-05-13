package com.nimbusds.openid.connect.sdk;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ScopeToken;


/**
 * Standard OpenID Connect scope token.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
 */
public class OIDCScopeToken extends ScopeToken {


	/**
	 * Informs the authorisation server that the client is making an OpenID 
	 * Connect request (REQUIRED). This scope token requests access to the
	 * {@code sub} claim. 
	 */
	public static final OIDCScopeToken OPENID =
		new OIDCScopeToken("openid", ScopeToken.Requirement.REQUIRED, new String[]{"sub"});
	
	
	/**
	 * Requests that access to the end-user's default profile claims at the 
	 * UserInfo endpoint be granted by the issued access token. These 
	 * claims are: {@code name}, {@code family_name}, {@code given_name}, 
	 * {@code middle_name}, {@code nickname}, {@code preferred_username}, 
	 * {@code profile}, {@code picture}, {@code website}, {@code gender}, 
	 * {@code birthdate}, {@code zoneinfo}, {@code locale}, and 
	 * {@code updated_time}. 
	 */
	public static final OIDCScopeToken PROFILE =
		new OIDCScopeToken("profile", new String[]{"name",
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
	                                               "updated_time"});
	
	
	/**
	 * Requests that access to the {@code email} and {@code email_verified}
	 * claims at the UserInfo endpoint be granted by the issued access 
	 * token.
	 */
	public static final OIDCScopeToken EMAIL =
		new OIDCScopeToken("email", new String[]{"email", "email_verified"});
	
	
	/**
	 * Requests that access to {@code address} claim at the UserInfo 
	 * endpoint be granted by the issued access token. 
	 */
	public static final OIDCScopeToken ADDRESS =
		new OIDCScopeToken("address", new String[]{"formatted",
	                                               "street_address",
	                                               "locality",
	                                               "region",
	                                               "postal_code",
	                                               "country"});
	
	
	/**
	 * Requests that access to the {@code phone_number} claim at the 
	 * UserInfo endpoint be granted by the issued access token. 
	 */
	public static final OIDCScopeToken PHONE =
		new OIDCScopeToken("phone", new String[]{"phone_number"});


	/**
	 * Requests that an OAuth 2.0 refresh token be issued that can be used
	 * to obtain an access token that grants access the end-user's UserInfo
	 * endpoint even when the user is not present (not logged in).
	 */
	public static final OIDCScopeToken OFFLINE_ACCESS =
		new OIDCScopeToken("offline_access", null);


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
	private OIDCScopeToken(final String value, 
		               final ScopeToken.Requirement requirement,
	                       final String[] claims) {
	
		super(value, requirement);
		
		if (claims != null)
			this.claims = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(claims)));

		else
			this.claims = null;
	}


	/**
	 * Creates a new OpenID Connect scope token. The requirement is set to
	 * {@link ScopeToken.Requirement#OPTIONAL optional}.
	 *
	 * @param value  The scope token value. Must not be {@code null}.
	 * @param claims The names of the associated claims. Must not be
	 *               {@code null}.
	 */
	private OIDCScopeToken(final String value, 
		               final String[] claims) {
	
		this(value, ScopeToken.Requirement.OPTIONAL, claims);
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
	 * @return The default claims request JSON object, {@code null} if not
	 *         applicable.
	 */
	public JSONObject getClaimsRequestJSONObject() {

		JSONObject req = new JSONObject();
		
		for (String claim: claims) {
		
			if (getRequirement() == ScopeToken.Requirement.REQUIRED) {
			
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