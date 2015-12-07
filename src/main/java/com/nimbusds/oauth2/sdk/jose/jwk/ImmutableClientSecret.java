package com.nimbusds.oauth2.sdk.jose.jwk;


import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.Immutable;


/**
 * Immutable client secret.
 */
@Immutable
public final class ImmutableClientSecret extends ImmutableJWKSet {


	/**
	 * Creates a new immutable client secret.
	 *
	 * @param id     The client identifier. Must not be {@code null}.
	 * @param secret The client secret. Must not be {@code null}.
	 */
	public ImmutableClientSecret(final ClientID id, final Secret secret) {

		this(id, new OctetSequenceKey.Builder(secret.getValueBytes()).build());
	}


	/**
	 * Creates a new immutable client secret.
	 *
	 * @param id     The client identifier. Must not be {@code null}.
	 * @param secret The client secret. Must not be {@code null}.
	 */
	public ImmutableClientSecret(final ClientID id, final OctetSequenceKey secret) {
		super(id, new JWKSet(secret));
	}


	/**
	 * Returns the client secret.
	 *
	 * @return The client secret.
	 */
	public OctetSequenceKey getClientSecret() {

		return (OctetSequenceKey) getJWKSet().getKeys().get(0);
	}


	@Override
	public List<JWK> get(final Identifier id, final JWKSelector jwkSelector) {
		// Owner not checked
		return jwkSelector.select(getJWKSet());
	}
}
