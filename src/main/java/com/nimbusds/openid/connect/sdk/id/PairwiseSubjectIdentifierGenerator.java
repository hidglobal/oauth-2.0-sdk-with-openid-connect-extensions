package com.nimbusds.openid.connect.sdk.id;


import com.nimbusds.oauth2.sdk.id.Subject;

/**
 * Generator of pairwise subject identifiers.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages, section 2.8.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public interface PairwiseSubjectIdentifierGenerator {


	/**
	 * Generates a new pairwise subject identifier from the specified
	 * sector identifier and local subject.
	 *
	 * @param sectorIdentifier The sector identifier. Must not be
	 *                         {@code null}.
	 * @param localSub         The local subject identifier. Must not be
	 *                         {@code null}.
	 *
	 * @return The pairwise subject identifier.
	 */
	public Subject generate(final String sectorIdentifier, final Subject localSub);
}
