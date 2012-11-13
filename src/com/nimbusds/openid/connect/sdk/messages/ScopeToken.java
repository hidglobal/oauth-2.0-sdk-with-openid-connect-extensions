package com.nimbusds.openid.connect.sdk.messages;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;


/**
 * Token in the {@link Scope} parameter of an {@link AuthorizationRequest}.
 * This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-13)
 */
@Immutable
public class ScopeToken {


	/**
	 * Enumeration of the {@link ScopeToken scope token} requirement 
	 * types.
	 */
	public static enum Type {
	
		/**
		 * The token must be present in the {@link Scope} parameter.
		 */
		REQUIRED,
		
		
		/**
		 * The token may be optionally included in the {@link Scope}
		 * parameter.
		 */
		OPTIONAL
	}


	/**
	 * Informs the authorisation server that the client is making an OpenID 
	 * Connect request (REQUIRED). This scope tokens requests access to 
	 * the {@code user_id} claim. 
	 */
	public static final ScopeToken OPENID =
		new ScopeToken("openid", ScopeToken.Type.REQUIRED, new String[]{"user_id"});
	
	
	/**
	 * Requests that access to the end-user's default profile claims at the 
	 * UserInfo endpoint be granted by the issued access token. These claims
	 * are: {@code name}, {@code family_name}, {@code given_name}, 
	 * {@code middle_name}, {@code nickname}, {@code preferred_username}, 
	 * {@code profile}, {@code picture}, {@code website}, {@code gender}, 
	 * {@code birthday}, {@code zoneinfo}, {@code locale}, and 
	 * {@code updated_time}. 
	 */
	public static final ScopeToken PROFILE =
		new ScopeToken("profile", new String[]{"name",
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
	                                               "updated_time"});
	
	
	/**
	 * Requests that access to the {@code email} and {@code email_verified}
	 * claims at the UserInfo endpoint be granted by the issued access 
	 * token.
	 */
	public static final ScopeToken EMAIL =
		new ScopeToken("email", new String[]{"email", "email_verified"});
	
	
	/**
	 * Requests that access to {@code address} claim at the UserInfo 
	 * endpoint be granted by the issued access token. 
	 */
	public static final ScopeToken ADDRESS =
		new ScopeToken("address", new String[]{"formatted",
	                                               "street_address",
	                                               "locality",
	                                               "region",
	                                               "postal_code",
	                                               "country"});
	
	
	/**
	 * Requests that access to the {@code phone_number} claim at the 
	 * UserInfo endpoint be granted by the issued access token. 
	 */
	public static final ScopeToken PHONE =
		new ScopeToken("phone", new String[]{"phone_number"});


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
	private ScopeToken(final String value, 
		           final ScopeToken.Type type,
	                   final String[] claims) {
	
		this.value = value;
		this.type = type;
		
		this.claims = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(claims)));
	}


	/**
	 * Creates a new scope token. The requirement type is set to
	 * {@link ScopeToken.Requirement#OPTIONAL optional}.
	 *
	 * @param value  The scope token as a string. Must not be {@code null}.
	 * @param claims The names of the associated claims. Must not be
	 *               {@code null}.
	 */
	private ScopeToken(final String value, 
		           final String[] claims) {
	
		this(value, ScopeToken.Type.OPTIONAL, claims);
	}

		
	/**
	 * Returns the requirement type of the scope token.
	 *
	 * @return The requirement type.
	 */
	public Type getType() {

		return type;
	}
	
	
	/**
	 * Returns the names of the associated claims.
	 *
	 * @return The names of the associated claims.
	 */
	public Set<String> getClaims() {

		return claims;
	}
	
	
	/**
	 * Gets a default claims request JSON object for the scope token.
	 *
	 * @return The default claims request JSON object.
	 */
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


	/**
	 * Returns the string identifier of the scope token.
	 *
	 * @return The string identifier.
	 */
	@Override
	public String toString() {

		return value;
	}


	/**
	 * Returns a hash code based on the scope token value.
	 *
	 * @return Hash code based on the scope token value.
	 */
	@Override
	public int hashCode() {

		return value.hashCode();
	}


	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the two objects are scope tokens with the
	 *         same value, otherwise {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {

		return object != null &&
		       object instanceof ScopeToken &&
		       this.toString().equals(object.toString());
	}
}
