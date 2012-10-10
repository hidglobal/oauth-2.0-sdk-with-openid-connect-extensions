package com.nimbusds.openid.connect.messages;


import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * The base abstract class for ID Token and UserInfo claim requests.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-10)
 */
public abstract class ClaimsRequest {


	/**
	 * The requested claims.
	 */
	protected JSONObject claims;
	
	
	/**
	 * Optional array of requested locales, by order of preference.
	 */
	protected LangTag[] preferredLocales;
	
	
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
	protected static LangTag[] parsePreferredLocales(final JSONObject object)
		throws LangTagException {
		
		LangTag[] preferredLocales = null;
		
		if (object.containsKey("preferred_locales") &&
		    object.get("preferred_locales") instanceof JSONArray) {

			JSONArray locales = (JSONArray)object.get("preferred_locales");

			// Compose list of preferred locales   
			preferredLocales = new LangTag[locales.size()];

			for (int i=0; i < locales.size(); i++) {
			
				Object item = locales.get(i);
				
				if (! (item instanceof String))
					throw new LangTagException("Invalid language tag at position " + i);

				preferredLocales[i] = LangTag.parse((String)item);
			}
		}
		
		return preferredLocales;
	}
	
	
	/**
	 * Creates a new claims request instance. The {@link #claims} is set to
	 * a new empty JSON object, {@link #preferredLocales} to {@code null}.
	 */
	protected ClaimsRequest() {
	
		claims = new JSONObject();
		
		preferredLocales = null;
	}
	
	
	/**
	 * Gets the resolved claims JSON object.
	 *
	 * @return The resolved claims object.
	 */
	public JSONObject getClaimsObject() {
	
		return claims;
	}
	
	
	/**
	 * Gets the resolved required claims.
	 *
	 * @return The names of the required claims.
	 */
	public Set<String> getRequiredClaims() {
	
		Set<String> requiredClaims = new HashSet<String>();
	
		for (Map.Entry<String,Object> claimEntry: claims.entrySet()) {
		
			if (claimEntry.getValue() == null) {
			
				requiredClaims.add(claimEntry.getKey());
			}	
			else if (claimEntry.getValue() instanceof JSONObject) {
			
				JSONObject claimDetails = (JSONObject)claimEntry.getValue();
				
				if (! claimDetails.containsKey("optional"))
					requiredClaims.add(claimEntry.getKey());
			}
		}
	
		return requiredClaims;
	}
	
	
	/**
	 * Gets the resolved optional claims.
	 *
	 * @return The names of the optional claims.
	 */
	public Set<String> getOptionalClaims() {
	
		Set<String> optionalClaims = new HashSet<String>();
		
		for (Map.Entry<String,Object> claimEntry: claims.entrySet()) {
			
			if (claimEntry.getValue() != null && claimEntry.getValue() instanceof JSONObject) {
			
				JSONObject claimDetails = (JSONObject)claimEntry.getValue();
				
				if (claimDetails.containsKey("optional"))
					optionalClaims.add(claimEntry.getKey());
			}
		}
		
		return optionalClaims;
	}
	
	
	/**
	 * Gets all resolved requested claims (required and optional).
	 *
	 * @return The names of all claims (required and optional).
	 */
	public Set<String> getClaims() {
	
		return claims.keySet();
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
