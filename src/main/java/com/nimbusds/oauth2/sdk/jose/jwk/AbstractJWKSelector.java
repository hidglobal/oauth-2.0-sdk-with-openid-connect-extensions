package com.nimbusds.oauth2.sdk.jose.jwk;


import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Abstract JSON Web Key (JWK) selector.
 */
@ThreadSafe
public abstract class AbstractJWKSelector {


	/**
	 * Identifier for the JWK selector.
	 */
	private final Identifier id;


	/**
	 * Creates a new abstract JWK selector.
	 *
	 * @param id Identifier for the JWK selector. Must not be {@code null}.
	 */
	public AbstractJWKSelector(final Identifier id) {
		if (id == null) {
			throw new IllegalArgumentException("The identifier must not be null");
		}
		this.id = id;
	}


	/**
	 * Returns the the identifier for the JWK selector.
	 *
	 * @return The identifier.
	 */
	public Identifier getIdentifier() {
		return id;
	}
}
