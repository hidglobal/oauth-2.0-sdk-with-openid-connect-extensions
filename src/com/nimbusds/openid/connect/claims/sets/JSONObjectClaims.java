package com.nimbusds.openid.connect.claims.sets;


import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.openid.connect.claims.ClaimWithLangTag;
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
	
	
	/**
	 * Puts the speicifed claims with optional language tags into a JSON 
	 * object.
	 *
	 * <p>Example:
	 * 
	 * <pre>
	 * {
	 *   "country"       : "USA",
	 *   "country#en"    : "USA",
	 *   "country#de_DE" : "Vereinigte Staaten",
	 *   "country#fr_FR" : "Etats Unis"
	 * }
	 * </pre>
	 *
	 * @param o      The JSON object. May be {@code null}.
	 * @param claims The claims. May be {@code null}.
	 */
	public static void putIntoJSONObject(final JSONObject o, final Map<LangTag,? extends ClaimWithLangTag> claims) {
	
		if (o == null || claims == null)
			return;
		
		Iterator <? extends ClaimWithLangTag> it = claims.values().iterator();
		
		while (it.hasNext()) {
		
			ClaimWithLangTag claim = it.next();
			
			o.put(claim.getClaimName(), claim.getClaimValue());
		}
	}
}
