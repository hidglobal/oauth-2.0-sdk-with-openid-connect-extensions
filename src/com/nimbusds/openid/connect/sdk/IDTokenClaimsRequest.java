package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseTypeSet;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;

import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;


/**
 * Resolved ID Token claims request. Specifies the claims to return with the ID
 * Token. These are determined from the following:
 *
 * <ul>
 *     <li>The {@link com.nimbusds.oauth2.sdk.ResponseTypeSet} passed with the
 *         {@code response_type} parameter of the original 
 *         {@link OIDCAuthorizationRequest}.
 *     <li>The optional OpenID request object passed with the
 *         {@code request} or {@code request_uri} parameter of the original
 *         {@link OIDCAuthorizationRequest}.
 * </ul>
 *
 * <p>This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, sections 2.1.1 and 2.1.1.1.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
 */
@Immutable
public class IDTokenClaimsRequest extends ClaimsRequest {


	/**
	 * The maximum required authentication age, in seconds; 0 if not 
	 * specified.
	 */
	private int maxAge = 0;


	/**
	 * The redirection URI.
	 */
	private final URL redirectURI;


	/**
	 * Optional state parameter.
	 */
	private final State state;
	
	
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
		claims.add("sub");
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
	 * @param redirectURI   The redirection URI, must not be {@code null}.
	 * @param state         Optional state parameter, {@code null} if not
	 *                      specified.
	 *
	 * @throws ResolveException If the ID Token claims request couldn't be
	 *                          resolved.
	 */
	public IDTokenClaimsRequest(final ResponseTypeSet rts, 
		                    final JSONObject idTokenObject,
		                    final URL redirectURI,
		                    final State state)
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

		this.redirectURI = redirectURI;

		this.state = state;
	}
	
	
	/**
	 * Gets the required subject (shorthand method).
	 *
	 * <p>Example claim structure:
	 *
	 * <pre>
	 * { "sub": {"value":"248289761001"}, ... }
	 * </pre>
	 *
	 * @return The required subject, {@code null} if not specified.
	 *
	 * @throws ResolveException If the required subject couldn't be
	 *                          resolved.
	 */
	public Subject getRequiredSubject()
		throws ResolveException {
	
		Object subjectObject = requestedClaims.get("sub");
		
		if (subjectObject == null)
			return null;
			
		if (! (subjectObject instanceof Map))
			throw new ResolveException("Unexpected \"sub\" type, must be a JSON object",
				                   OIDCError.INVALID_OPENID_REQUEST_OBJECT,
				                   redirectURI, state, null);
			
		Object subValue = ((Map)subjectObject).get("value");
		
		if (subValue == null)
			return null;

		if (! (subValue instanceof String))
			throw new ResolveException("Unexpected \"sub\" value type, must be a JSON string",
				                   OIDCError.INVALID_OPENID_REQUEST_OBJECT,
				                   redirectURI, state, null);
		
		return new Subject((String)subValue);
	}
	
	
	/**
	 * Gets the requested Authentication Context Class References (ACRs) 
	 * (shorthand method).
	 *
	 * <p>Example claim structure:
	 *
	 * <pre>
	 * { "acr": {"values":["2","http://id.incommon.org/assurance/bronze"]}, ... }
	 * </pre>
	 *
	 * @return The requested ACRs, {@code null} if not specified.
	 *
	 * @throws ResolveException If the required ACRs couldn't be resolved.
	 */
	public ACRRequest getRequestedACRs()
		throws ResolveException {
	
		Object acrObject = requestedClaims.get("acr");
		
		if (acrObject == null)
			return null;
			
		if (! (acrObject instanceof JSONObject))
			throw new ResolveException("Unexpected \"acr\" type, must be a JSON object",
				                   OIDCError.INVALID_OPENID_REQUEST_OBJECT,
				                   redirectURI, state, null);
	
		
		Object acrValues = ((JSONObject)acrObject).get("values");
		Object essentialValue = ((JSONObject)acrObject).get("essential");
		
		if (acrValues == null)
			return null;
			
		if (! (acrValues instanceof List))
			throw new ResolveException("Unexpected \"acr\" values type, must be a JSON array",
				                   OIDCError.INVALID_OPENID_REQUEST_OBJECT,
				                   redirectURI, state, null);
	
		ClaimRequirement req = ClaimRequirement.VOLUNTARY;

		if (essentialValue != null && essentialValue instanceof Boolean &&
		    (Boolean)essentialValue)
			req = ClaimRequirement.ESSENTIAL;


		int numElements = ((List)acrValues).size();
	
		ACR[] acr = new ACR[numElements];
		
		for (int i=0; i < numElements; i++) {
		
			if (! (((List)acrValues).get(i) instanceof String))
				throw new ResolveException("Unexpected ACR value, must be a JSON string",
					                   OIDCError.INVALID_OPENID_REQUEST_OBJECT,
					                   redirectURI, state, null);
			
			acr[i] = new ACR((String)((List)acrValues).get(i));
		}
		
		return new ACRRequest(req, acr);
	}
	
	
	/**
	 * Gets the required maximum authentication age (shorthand method).
	 *
	 * @return The maximum authentication age, in seconds; 0 if not 
	 *         specified.
	 */
	public int getRequiredMaxAge()
		throws ResolveException {
	
		return maxAge;
	}
}
