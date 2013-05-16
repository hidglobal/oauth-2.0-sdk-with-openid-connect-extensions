package com.nimbusds.openid.connect.sdk;


import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;


/**
 * Base abstract class for resolved ID Token and UserInfo claim requests.
 *
 * <p>Used to return the following resolved claims request information:
 *
 * <ul>
 *     <li>{@link #getRequiredClaims The required claims} that the 
 *         authorisation server must provide with the response.
 *     <li>Claims requested by the client:
 *         <ul>
 *             <li>{@link #getRequestedEssentialClaims The requested essential
 *                 claims} that are required for providing the service 
 *                 requested by the end-user.
 *             <li>{@link #getRequestedVoluntaryClaims The requested voluntary
 *                 claims} that are used to provide non-essential tasks offered
 *                 to the end-user.
 *         </ul>
 * </ul>
 *
 * <p>The underlying resolved claims request as a JSON object can be retrieved 
 * with the {@link #getRequestedClaimsObject} method.
 *
 * <p>Related specifications: 
 * 
 * <ul>
 *     <li>OpenID Connect Messages, section 2.1.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public abstract class ClaimsRequest {


	/**
	 * Claims that the authorisation server must provide with the response.
	 */
	protected Set<String> requiredClaims;
		 
	 
	/**
	 * Claims requested by the client that the authorisation server may 
	 * choose to provide with the response according to policy and end-user
	 * consent. These may be marked as essential or voluntary according to
	 * OpenID Connect Messages 2.1.1.1.3.
	 */
	protected JSONObject requestedClaims;
	
	
	/**
	 * Creates a new claims request. The {@link #requiredClaims} field is
	 * set to a new empty set. The {@link #requestedClaims} field is set to 
	 * a new empty JSON object.
	 */
	protected ClaimsRequest() {
	
		requiredClaims = new HashSet<String>();
		
		requestedClaims = new JSONObject();
	}
	
	
	/**
	 * Gets the required claims that the authorisation server must provide
	 * with the response.
	 *
	 * @return The names of the required claims, as a read-only set.
	 */
	public Set<String> getRequiredClaims() {
	
		return Collections.unmodifiableSet(requiredClaims);
	}
	
	
	/**
	 * Gets the resolved JSON object representing the claims requested by 
	 * the client. The JSON object has the format of the "claims" member of
	 * an OpenID Connect request object. It can specify claims marked as 
	 * essential or voluntary according to OpenID Connect Messages 
	 * 2.1.1.1.3.
	 *
	 * <p>Example resolved UserInfo claims request:
	 *
	 * <pre>
	 * {
         *   "name"           : { "essential" : true },
         *   "nickname"       : null,
         *   "email"          : { "essential" : true },
         *   "email_verified" : { "essential" : true },
         *   "picture"        : null
         * }
	 * </pre>
	 *
	 * <p>Example resolved ID Token claims request:
	 *
	 * <pre>
	 * {
         *   "auth_time" : { "essential": true },
         *   "acr"       : { "values":["2"] }
         * }
	 * </pre>
	 *
	 * @return The requested claims JSON object.
	 */
	public JSONObject getRequestedClaimsObject() {
	
		return requestedClaims;
	}
	
	
	/**
	 * Gets those claims requested by the client that are marked as 
	 * essential. Claims marked as essential by the client indicate that 
	 * they are required for providing the service requested by the 
	 * end-user.
	 *
	 * @return The names of the requested essential claims, as a read-only 
	 *         set, empty set if none.
	 */
	public Set<String> getRequestedEssentialClaims() {
	
		Set<String> essentialClaims = new HashSet<String>();
	
		// Claims marked as essential must have a JSON object value
		// with an "essential" property set to "true"
		for (Map.Entry<String,Object> claim: requestedClaims.entrySet()) {
		
			Object value = claim.getValue();
			
			if (value == null || !(value instanceof JSONObject))
				continue;
			
			JSONObject claimDetails = (JSONObject)value;
			
			if (  claimDetails.get("essential") == null ||
			    !(claimDetails.get("essential") instanceof Boolean))
				continue;
				
			boolean claimIsEssential = (Boolean)claimDetails.get("essential");
			
			if (claimIsEssential)
				essentialClaims.add(claim.getKey());
		}
	
		return Collections.unmodifiableSet(essentialClaims);
	}
	
	
	/**
	 * Gets those claims requested by the client that are marked as 
	 * voluntary. Claims marked as voluntary are used to perform 
	 * non-essential tasks offered to the end-user.
	 *
	 * @return The names of the requested voluntary claims, as a read-only
	 *         set, empty set if none.
	 */
	public Set<String> getRequestedVoluntaryClaims() {
	
		Set<String> voluntaryClaims = new HashSet<String>();
		
		// Claims with a value of null or a JSON object value
		// with an "essential" property set to "false"
		for (Map.Entry<String,Object> claim: requestedClaims.entrySet()) {
			
			Object value = claim.getValue();
			
			if (value == null || !(value instanceof JSONObject)) {
			
				voluntaryClaims.add(claim.getKey());
				continue;
			}
			
			JSONObject claimDetails = (JSONObject)value;
			
			if (  claimDetails.get("essential") == null ||
			    !(claimDetails.get("essential") instanceof Boolean)) {
			    
			    	voluntaryClaims.add(claim.getKey());
				continue;
			}
				
			boolean claimIsEssential = (Boolean)claimDetails.get("essential");
			
			if (! claimIsEssential)
				voluntaryClaims.add(claim.getKey());
		}
		
		return Collections.unmodifiableSet(voluntaryClaims);
	}
	
	
	/**
	 * Gets all claims requested by the client (essential and voluntary).
	 *
	 * @return The names of all requested claims (essential and voluntary),
	 *         as a read-only set, empty set if none.
	 */
	public Set<String> getClaimNames() {
	
		return Collections.unmodifiableSet(requestedClaims.keySet());
	}
}
