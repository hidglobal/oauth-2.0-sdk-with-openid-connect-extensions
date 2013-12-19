package com.nimbusds.openid.connect.sdk.claims;


/**
 * Enumeration of the claim requirement types.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.5.1.
 * </ul>
 */
public enum ClaimRequirement {


	/**
	 * Essential claim.
	 */
	ESSENTIAL,


	/**
	 * Voluntary claim.
	 */
	VOLUNTARY
}