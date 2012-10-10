package com.nimbusds.openid.connect.messages;


import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;


/**
 * The base abstract class for resolved ID Token and UserInfo claim requests.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-10)
 */
public abstract class ClaimsRequest {


	/**
	 * The resolved requested claims.
	 */
	protected JSONObject claims;
	
	
	/**
	 * Creates a new claims request. The {@link #claims} field is set to
	 * a new empty JSON object.
	 */
	protected ClaimsRequest() {
	
		claims = new JSONObject();
	}
	
	
	/**
	 * Gets the resolved claims JSON object.
	 *
	 * @return The resolved claims JSON object.
	 */
	public JSONObject getClaimsObject() {
	
		return claims;
	}
	
	
	/**
	 * Gets the names of the requested essential claims. Claims marked as 
	 * essential by the client are required to ensure a smooth authorisation
	 * for the specified task requested by the end-user.
	 *
	 * @return The names of the requested essential claims.
	 */
	public Set<String> getEssentialClaimNames() {
	
		Set<String> essentialClaims = new HashSet<String>();
	
		// Claims marked as essential must have a JSON object value
		// with an "essential" property set to "true"
		for (Map.Entry<String,Object> claimEntry: claims.entrySet()) {
		
			Object value = claimEntry.getValue();
			
			if (value == null || !(value instanceof JSONObject))
				continue;
			
			JSONObject claimDetails = (JSONObject)value;
			
			if (claimDetails.get("essential") == null ||
			    !(claimDetails.get("essential") instanceof Boolean))
				continue;
				
			boolean claimIsEssential = (Boolean)claimDetails.get("essential");
			
			if (claimIsEssential)
				essentialClaims.add(claimEntry.getKey());
		}
	
		return essentialClaims;
	}
	
	
	/**
	 * Gets the names of the requested voluntary claims. Claims that are 
	 * marked as voluntary by the client or are assumed as such by default, 
	 * are requested by the client to perform non-essential tasks offered to
	 * the end-user.
	 *
	 * @return The names of the requested volunatry claims.
	 */
	public Set<String> getVoluntaryClaimNames() {
	
		Set<String> voluntaryClaims = new HashSet<String>();
		
		// Claims with a value of null or a JSON object value
		// with an "essential" property set to "false"
		for (Map.Entry<String,Object> claimEntry: claims.entrySet()) {
			
			Object value = claimEntry.getValue();
			
			if (value == null || !(value instanceof JSONObject)) {
			
				voluntaryClaims.add(claimEntry.getKey());
				continue;
			}
			
			JSONObject claimDetails = (JSONObject)value;
			
			if (claimDetails.get("essential") == null ||
			    !(claimDetails.get("essential") instanceof Boolean)) {
			    
			    	voluntaryClaims.add(claimEntry.getKey());
				continue;
			}
				
			boolean claimIsEssential = (Boolean)claimDetails.get("essential");
			
			if (! claimIsEssential)
				voluntaryClaims.add(claimEntry.getKey());
		}
		
		return voluntaryClaims;
	}
	
	
	/**
	 * Gets the names of all requested claims (essential and voluntary).
	 *
	 * @return The names of all claims (essential and voluntary).
	 */
	public Set<String> getClaimNames() {
	
		return claims.keySet();
	}
}
