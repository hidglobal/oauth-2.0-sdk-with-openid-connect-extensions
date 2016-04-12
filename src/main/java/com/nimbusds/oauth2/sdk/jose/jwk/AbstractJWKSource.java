package com.nimbusds.oauth2.sdk.jose.jwk;


import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Abstract JSON Web Key (JWK) source.
 */
@ThreadSafe
@Deprecated
abstract class AbstractJWKSource implements JWKSource {
	

	/**
	 * The key owner.
	 */
	private final Identifier owner;


	/**
	 * Creates a new abstract JWK source.
	 *
	 * @param owner The key owner identifier. Typically the OAuth 2.0
	 *              server issuer ID, or client ID. Must not be
	 *              {@code null}.
	 */
	public AbstractJWKSource(final Identifier owner) {
		if (owner == null) {
			throw new IllegalArgumentException("The owner identifier must not be null");
		}
		this.owner = owner;
	}


	/**
	 * Returns the owner identifier.
	 *
	 * @return The owner identifier.
	 */
	public Identifier getOwner() {

		return owner;
	}
}
