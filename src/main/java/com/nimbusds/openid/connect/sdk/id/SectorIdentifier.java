package com.nimbusds.openid.connect.sdk.id;


import java.net.URI;

import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.Immutable;


/**
 * Sector identifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
@Immutable
public final class SectorIdentifier extends Identifier {


	/**
	 * Ensures the specified URI contains a host component.
	 *
	 * @param sectorURI The sector identifier URI. Must contain a host
	 *                  component and must not be {@code null}.
	 *
	 * @return The host component.
	 */
	private static String ensureHostComponent(final URI sectorURI) {

		String host = sectorURI.getHost();

		if (host == null) {
			throw new IllegalArgumentException("The URI must contain a host component");
		}

		return host;
	}
	

	/**
	 * Creates a new sector identifier for the specified host.
	 *
	 * @param host The host. Must not be empty or {@code null}.
	 */
	public SectorIdentifier(final String host) {
		super(host);
	}


	/**
	 * Creates a new sector identifier for the specified URI.
	 *
	 * @param sectorURI The sector identifier URI. Must contain a host
	 *                  component and must not be {@code null}.
	 */
	public SectorIdentifier(final URI sectorURI) {
		super(ensureHostComponent(sectorURI));
	}
}
