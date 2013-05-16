package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;


/**
 * Authentication Context Class Reference (ACR) request.
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable 
public final class ACRRequest {


	/**
	 * The requirement type.
	 */
	private final ClaimRequirement requirement;


	/**
	 * The requested ACR values.
	 */
	private final ACR[] values;


	/**
	 * Creates a new Authentication Context Class Reference (ACR) request.
	 *
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param values      The requested ACR values, in order of preference.
	 *                    Must not be {@code null}.
	 */
	public ACRRequest(final ClaimRequirement requirement, final ACR[] values) {

		if (requirement == null)
			throw new IllegalArgumentException("The ACR claim requirement must not be null");

		this.requirement = requirement;


		if (values == null)
			throw new IllegalArgumentException("The requested ACR values must not be null");

		this.values = values;
	}
	

	/**
	 * Gets the ACR claim requirement.
	 *
	 * @return The claim requirement.
	 */
	public ClaimRequirement getRequirement() {

		return requirement;
	}


	/**
	 * Gets the requested ACR values.
	 *
	 * @return The requested ACR values, in order of preference.
	 */
	public ACR[] getValues() {

		return values;
	}
}