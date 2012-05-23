package com.nimbusds.openid.connect.claims.sets;


import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.claims.GenericClaim;


/**
 * Claims set serialisable to a JSON object.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-23)
 */
public abstract class JSONObjectClaims {


	/**
	 * Custom (non-reserved) claims, empty if none.
	 */
	protected Map<String,GenericClaim> customClaims = new HashMap<String,GenericClaim>();
	
	
	/**
	 * Returns a JSON object representation of the claims set.
	 *
	 * @return The JSON object representation.
	 */
	public abstract JSONObject toJSONObject();
	
	
	/**
	 * Gets the custom (non-reserved) claims of the claims set.
	 *
	 * @return The custom claims, empty map if none.
	 */
	public Map<String, GenericClaim> getCustomClaims() {
	
		return customClaims;
	}
	
	
	/**
	 * Adds a custom (non-reserved) claim to the claims set.
	 *
	 * @param customClaim The custom claim to add. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the custom claim name conflicts 
	 *                                  with a reserved claim name.
	 */
	public abstract void addCustomClaim(final GenericClaim customClaim);
}
