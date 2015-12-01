package com.nimbusds.openid.connect.sdk.jwt;


import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Abstract key selector.
 */
@ThreadSafe
public abstract class AbstractKeySelector {


	/**
	 * Identifier for key selector.
	 */
	private final Identifier id;


	/**
	 * Creates a new abstract key selector.
	 *
	 * @param id The the identifier for the key selector. Must not be
	 *           {@code null}.
	 */
	public AbstractKeySelector(final Identifier id) {
		if (id == null) {
			throw new IllegalArgumentException("The JWK set source identifier must not be null");
		}
		this.id = id;
	}


	/**
	 * Returns the the identifier for the key selector.
	 *
	 * @return The identifier.
	 */
	public Identifier getIdentifier() {
		return id;
	}
}
