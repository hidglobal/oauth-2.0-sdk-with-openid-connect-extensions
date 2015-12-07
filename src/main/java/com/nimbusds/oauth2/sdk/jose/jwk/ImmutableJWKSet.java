package com.nimbusds.oauth2.sdk.jose.jwk;


import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.Immutable;


/**
 * Immutable JSON Web Key (JWK) set. Intended for a JWK set specified by value.
 */
@Immutable
public class ImmutableJWKSet extends AbstractJWKSource {


	/**
	 * The JWK set.
	 */
	private final JWKSet jwkSet;


	/**
	 * Creates a new immutable JWK set.
	 *
	 * @param id     The JWK set owner identifier. Typically the OAuth 2.0
	 *               server issuer ID, or client ID. Must not be
	 *               {@code null}.
	 * @param jwkSet The JWK set. Must not be {@code null}.
	 */
	public ImmutableJWKSet(final Identifier id, final JWKSet jwkSet) {
		super(id);
		if (jwkSet == null) {
			throw new IllegalArgumentException("The JWK set must not be null");
		}
		this.jwkSet = jwkSet;
	}


	/**
	 * Returns the JWK set.
	 *
	 * @return The JWK set.
	 */
	public JWKSet getJWKSet() {
		return jwkSet;
	}


	@Override
	public List<JWK> get(final Identifier id, final JWKSelector jwkSelector) {
		// Owner not checked, mismatch for client secret (see ImmutableClientSecret)
		return jwkSelector.select(jwkSet);
	}
}
