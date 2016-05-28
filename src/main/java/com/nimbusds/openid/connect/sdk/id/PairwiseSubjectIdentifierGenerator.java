package com.nimbusds.openid.connect.sdk.id;


import java.net.URI;

import com.nimbusds.oauth2.sdk.id.Subject;


/**
 * Generator of pairwise subject identifiers.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
public abstract class PairwiseSubjectIdentifierGenerator {


	/**
	 * Generates a new pairwise subject identifier from the specified
	 * sector identifier URI and local subject.
	 *
	 * @param sectorURI The sector identifier URI. Its scheme should be
	 *                  "https", must include a host portion and must not
	 *                  be {@code null}.
	 * @param localSub  The local subject identifier. Must not be
	 *                  {@code null}.
	 *
	 * @return The pairwise subject identifier.
	 */
	public Subject generate(final URI sectorURI, final Subject localSub) {

		return generate(new SectorIdentifier(sectorURI), localSub);
	}


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
	public abstract Subject generate(final SectorIdentifier sectorIdentifier, final Subject localSub);
}
