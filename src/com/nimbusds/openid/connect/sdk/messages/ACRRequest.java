package com.nimbusds.openid.connect.sdk.messages;


import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.Claim;


/**
 * Authentication Context Class Reference (ACR) request.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-20)
 */
@Immutable 
public class ACRRequest {


	/**
	 * The requirement type.
	 */
	private final Claim.Requirement requirement;


	/**
	 * The requested ACR levels.
	 */
	private final ACR[] levels;


	/**
	 * Creates a new Authentication Context Class Reference (ACR) request.
	 *
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param levels      The requested ACR levels, in order of preference.
	 *                    Must not be {@code null}.
	 */
	public ACRRequest(final Claim.Requirement requirement, final ACR[] levels) {

		if (requirement == null)
			throw new IllegalArgumentException("The ACR claim requirement must not be null");

		this.requirement = requirement;


		if (levels == null)
			throw new IllegalArgumentException("The requested ACR levels must not be null");

		this.levels = levels;
	}
	

	/**
	 * Gets the ACR claim requirement.
	 *
	 * @return The claim requirement.
	 */
	public Claim.Requirement getRequirement() {

		return requirement;
	}


	/**
	 * Gets the requested ACR levels.
	 *
	 * @return The requested ACR levels, in order of preference.
	 */
	public ACR[] getLevels() {

		return levels;
	}
}