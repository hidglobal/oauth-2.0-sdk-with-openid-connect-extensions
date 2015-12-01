package com.nimbusds.openid.connect.sdk.jwt;


import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Static singleton JWK set source. Intended for immutable JWK sets specified
 * by value and tied to a single source.
 */
@ThreadSafe
public class StaticSingletonJWKSetSource extends AbstractSingletonJWKSetSource {


	/**
	 * The JWK set.
	 */
	private final JWKSet jwkSet;


	/**
	 * Creates a new static singleton JWK set source.
	 *
	 * @param id     The source identifier. Must not be {@code null}.
	 * @param jwkSet The JWK set. Must not be {@code null}.
	 */
	public StaticSingletonJWKSetSource(final Identifier id, final JWKSet jwkSet) {
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
	public List<JWK> get(final Identifier id, final JWKMatcher jwkMatcher) {
		if (! getSourceID().equals(id)) {
			return Collections.emptyList();
		}
		JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
		return jwkSelector.select(jwkSet);
	}
}
