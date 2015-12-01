package com.nimbusds.openid.connect.sdk.jwt;


import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Abstract key selector with JWK set source.
 */
@ThreadSafe
abstract class AbstractKeySelectorWithJWKSetSource extends AbstractKeySelector {
	

	/**
	 * The JWK set source.
	 */
	private final JWKSetSource jwkSetSource;


	/**
	 * Creates a new abstract key selector with a JWK set source.
	 *
	 * @param id           The the identifier for the key selector. Must
	 *                     not be {@code null}.
	 * @param jwkSetSource The JWK set source. Must not be {@code null}.
	 */
	public AbstractKeySelectorWithJWKSetSource(final Identifier id, final JWKSetSource jwkSetSource) {
		super(id);
		if (jwkSetSource == null) {
			throw new IllegalArgumentException("The JWK set source must not be null");
		}
		this.jwkSetSource = jwkSetSource;
	}


	/**
	 * Returns the JWK set source.
	 *
	 * @return The JWK set source.
	 */
	public JWKSetSource getJWKSetSource() {
		return jwkSetSource;
	}
}
