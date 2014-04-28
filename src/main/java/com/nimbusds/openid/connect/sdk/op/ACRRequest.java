package com.nimbusds.openid.connect.sdk.op;


import java.util.ArrayList;
import java.util.List;

import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;


/**
 * Resolved authentication Context Class Reference (ACR) request.
 */
@Immutable 
public final class ACRRequest {


	/**
	 * The essential ACR values.
	 */
	private final List<ACR> essentialACRs;


	/**
	 * The voluntary ACR values.
	 */
	private final List<ACR> voluntaryACRs;


	/**
	 * Creates a new Authentication Context Class Reference (ACR) request.
	 *
	 * @param essentialACRs The requested essential ACR values, by order of
	 *                      preference, {@code null} if not specified.
	 * @param voluntaryACRs The requested voluntary ACR values, by order of
	 *                      preference, {@code null} if not specified.
	 */
	public ACRRequest(final List<ACR> essentialACRs, final List<ACR> voluntaryACRs) {

		this.essentialACRs = essentialACRs;
		this.voluntaryACRs = voluntaryACRs;
	}
	

	/**
	 * Gets the requested essential ACR values.
	 * 
	 * @return The essential ACR values, by order of preference, 
	 *         {@code null} if not specified.
	 */
	public List<ACR> getEssentialACRs() {
		
		return essentialACRs;
	}
	
	
	/**
	 * Gets the requested voluntary ACR values.
	 * 
	 * @return The voluntary ACR values, by order of preference, 
	 *         {@code null} if not specified.
	 */
	public List<ACR> getVoluntaryACRs() {
		
		return voluntaryACRs;
	}
	
	
	/**
	 * Checks if this authentication Context Class Reference (ACR) request
	 * has not essential or voluntary values specified.
	 * 
	 * @return {@code true} if this ACR request doesn't specify any 
	 *         essential or voluntary values, else {@code false}.
	 */
	public boolean isEmpty() {

		return !(essentialACRs != null && !essentialACRs.isEmpty()) &&
		       !(voluntaryACRs != null && !voluntaryACRs.isEmpty());
	}
	
	
	
	/**
	 * Resolves the requested essential and voluntary ACR values from the
	 * specified OpenID Connect authentication request.
	 * 
	 * @param authRequest The OpenID Connect authentication request. Should
	 *                    be resolved. Must not be {@code null}.
	 * 
	 * @return The resolved ACR request.
	 */
	public static ACRRequest resolve(final AuthenticationRequest authRequest) {
		
		List<ACR> essentialACRs = null;
		List<ACR> voluntaryACRs = null;
		
		ClaimsRequest claimsRequest = authRequest.getClaims();
		
		if (claimsRequest != null) {
			
			for (ClaimsRequest.Entry claimEntry: claimsRequest.getIDTokenClaims()) {
				
				if (! claimEntry.getClaimName().equals("acr"))
					continue;
				
				if (claimEntry.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL)) {
					
					essentialACRs = new ArrayList<>();
					
					if (claimEntry.getValue() != null)
						essentialACRs.add(new ACR(claimEntry.getValue()));
					
					if (claimEntry.getValues() != null) {
						
						for (String v: claimEntry.getValues())
							essentialACRs.add(new ACR(v));
					}
					
				} else {
					voluntaryACRs = new ArrayList<>();
					
					if (claimEntry.getValue() != null)
						voluntaryACRs.add(new ACR(claimEntry.getValue()));
					
					if (claimEntry.getValues() != null) {
						
						for (String v: claimEntry.getValues())
							voluntaryACRs.add(new ACR(v));
					}
				}
			}
		}
		
		
		List<ACR> topLevelACRs = authRequest.getACRValues();
		
		if (topLevelACRs != null) {
			
			if (voluntaryACRs == null)
				voluntaryACRs = new ArrayList<>();
			
			voluntaryACRs.addAll(topLevelACRs);
		}
		
		return new ACRRequest(essentialACRs, voluntaryACRs);
	}
}