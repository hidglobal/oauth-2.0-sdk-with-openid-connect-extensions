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
public final class SectorID extends Identifier {


	/**
	 * Ensures the specified URI has a {@code https} scheme.
	 *
	 * @param sectorURI The URI. Must have a {@code https} scheme and not
	 *                  be {@code null}.
	 */
	public static void ensureHTTPScheme(final URI sectorURI) {

		if (! "https".equalsIgnoreCase(sectorURI.getScheme())) {
			throw new IllegalArgumentException("The URI must have a https scheme");
		}
	}


	/**
	 * Ensures the specified URI contains a host component.
	 *
	 * @param sectorURI The URI. Must contain a host component and not be
	 *                  {@code null}.
	 *
	 * @return The host component.
	 */
	public static String ensureHostComponent(final URI sectorURI) {

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
	public SectorID(final String host) {
		super(host);
	}


	/**
	 * Creates a new sector identifier for the specified URI.
	 *
	 * @param sectorURI The sector URI. Must contain a host component and
	 *                  must not be {@code null}.
	 */
	public SectorID(final URI sectorURI) {
		super(ensureHostComponent(sectorURI));
	}
}
