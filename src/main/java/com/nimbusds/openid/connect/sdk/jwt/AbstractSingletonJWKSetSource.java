package com.nimbusds.openid.connect.sdk.jwt;


import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Abstract singleton JWK set source.
 */
@ThreadSafe
abstract class AbstractSingletonJWKSetSource implements JWKSetSource {
	

	/**
	 * The source identifier.
	 */
	private final Identifier id;


	/**
	 * Creates a new abstract singleton JWK set source.
	 *
	 * @param id The source identifier. Must not be {@code null}.
	 */
	public AbstractSingletonJWKSetSource(final Identifier id) {
		if (id == null) {
			throw new IllegalArgumentException("The identifier must not be null");
		}
		this.id = id;
	}


	/**
	 * Returns the source identifier.
	 *
	 * @return The source identifier.
	 */
	public Identifier getSourceID() {

		return id;
	}
}
