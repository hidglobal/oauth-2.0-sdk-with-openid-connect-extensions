package com.nimbusds.openid.connect.messages;


import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTagException;


/**
 * Resolved ID Token claims request. Specifies the claims to return with the
 * ID Token. These are determined from the following:
 *
 * <ul>
 *     <li>The {@link ResponseTypeSet} passed with the {@code response_type}
 *         parameter of the original {@link AuthorizationRequest}.
 *     <li>The optional OpenID Connect request object passed with the
 *         {@code request} or {@code request_uri} parameter of the original
 *         {@link AuthorizationRequest}.
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, sections 2.1.1 and 2.1.2.1.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-11)
 */
public class IDTokenClaimsRequest extends ClaimsRequest {


	/**
	 * The maximum authentication age, in seconds. -1 if not specified.
	 */
	private int maxAge = -1;
	
	
	/**
	 * Resolves the required ID Token claims.
	 *
	 * @param rts The response type set. Obtained from the 
	 *            {@code response_type} authorisation request parameter.
	 *            Must not be {@code null}.
	 *
	 * @return The names of the resolved required ID Token claims, as a
	 *         read-only set.
	 */
	public static Set<String> resolveRequiredClaims(final ResponseTypeSet rts) {
	
		Set<String> claims = new HashSet<String>();
		
		claims.add("iss");
		claims.add("user_id");
		claims.add("aud");
		claims.add("exp");
		claims.add("iat");
		
		// Conditionally required claims
		
		if (rts.impliesImplicitFlow())
			claims.add("nonce");
		
		if (rts.impliesImplicitFlow() && rts.contains(ResponseType.TOKEN))
			claims.add("at_hash");
		
		if (rts.impliesImplicitFlow() && rts.contains(ResponseType.CODE))
			claims.add("c_hash");
		
		return Collections.unmodifiableSet(claims);
	}
	
	
	/**
	 * Creates a new resolved ID Token claims request.
	 *
	 * @param rts           The response type set. Obtained from the 
	 *                      {@code response_type} authorisation request 
	 *                      parameter. Must not be {@code null}.
	 * @param idTokenObject The {@code id_token} JSON object from the 
	 *                      optional OpenID request object. Obtained from 
	 *                      the decoded {@code request} or 
	 *                      {@code request_uri} authorisation request 
	 *                      parameter. {@code null} if not specified.
	 *
	 * @throws ResolveException If the ID Token claims request couldn't be
	 *                          resolved.
	 */
	public IDTokenClaimsRequest(final ResponseTypeSet rts, final JSONObject idTokenObject)
		throws ResolveException {
	
		// Set required claims
		requiredClaims.addAll(resolveRequiredClaims(rts));
		
		if (idTokenObject != null) {
		
			if (idTokenObject.containsKey("claims") &&
		            idTokenObject.get("claims") instanceof JSONObject) {
		
				// Add claims
				JSONObject additionalClaims = (JSONObject)idTokenObject.get("claims");

				requestedClaims.putAll(additionalClaims);
			}
			
			
			// Parse max_age
			if (idTokenObject.get("max_age") != null &&
			    idTokenObject.get("max_age") instanceof Number)
			    	maxAge = ((Number)idTokenObject.get("max_age")).intValue();
		}
	}
	
	
	/**
	 * Gets the required user ID (shorthand method).
	 *
	 * <p>Example claim structure:
	 *
	 * <pre>
	 * { "user_id": {"value":"248289761001"}, ... }
	 * </pre>
	 *
	 * @return The required user ID, {@code null} if not specified.
	 *
	 * @throws ResolveException If the required user ID couldn't be
	 *                          correctly resolved.
	 */
	public String getUserID()
		throws ResolveException {
	
		Object uidObject = requestedClaims.get("user_id");
		
		if (uidObject == null)
			return null;
			
		if (! (uidObject instanceof JSONObject))
			throw new ResolveException("Unexpected \"user_id\" type, must be a JSON object");
			
		Object uidValue = ((JSONObject)uidObject).get("value");
		
		if (uidValue == null)
			return null;

		if (! (uidValue instanceof String))
			throw new ResolveException("Unexpected \"value\" type, must be a JSON string");
			
		return (String)uidValue;
	}
	
	
	/**
	 * Gets the required Authentication Context Class References (ACRs) 
	 * (shorthand method).
	 *
	 * <p>Example claim structure:
	 *
	 * <pre>
	 * { "acr": {"values":["2","http://id.incommon.org/assurance/bronze"]}, ... }
	 * </pre>
	 *
	 * @return The required ACRs, {@code null} if not specified.
	 *
	 * @throws ResolveException If the required ACRs couldn't be correctly
	 *                          resolved.
	 */
	public String[] getAuthenticationContextClassReference()
		throws ResolveException {
	
		Object acrObject = requestedClaims.get("acr");
		
		if (acrObject == null)
			return null;
			
		if (! (acrObject instanceof JSONObject))
			throw new ResolveException("Unexpected \"acr\" type, must be a JSON object");
	
		Object acrValues = ((JSONObject)acrObject).get("values");
		
		if (acrValues == null)
			return null;
			
		if (! (acrValues instanceof JSONArray))
			throw new ResolveException("Unexpected \"acr\" values type, must be a JSON array");
	
		int numElements = ((List)acrValues).size();
	
		String[] acr = new String[numElements];
		
		for (int i=0; i < numElements; i++) {
		
			if (! (((List)acrValues).get(i) instanceof String))
				throw new ResolveException("Unexpected ACR value, must be a JSON string");
			
			acr[i] = (String)((List)acrValues).get(i);
		}
		
		return acr;
	}
	
	
	/**
	 * Gets the expected max authentication age (shorthand method).
	 *
	 * @return The maximum authentication age, in seconds. -1 if not 
	 *         specified.
	 */
	public int getMaxAge()
		throws ResolveException {
	
		return maxAge;
	}
}
