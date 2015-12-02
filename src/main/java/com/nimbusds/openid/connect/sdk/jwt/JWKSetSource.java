package com.nimbusds.openid.connect.sdk.jwt;


import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * JSON Web Key (JWK) set source. Exposes a method for selecting keys for a
 * given party (OpenID Provider or Relying Party) based on specified criteria.
 * Implementations must be thread-safe.
 */
public interface JWKSetSource {
	

	/**
	 * Retrieves a JWK set.
	 *
	 * @param id         Identifier for the JWK set source, typically an
	 *                   OpenID Provider issuer ID, or client ID. Must not
	 *                   be {@code null}.
	 * @param jwkMatcher A matcher specifying the parameters for the JWKs
	 *                   to select. Must not be {@code null}.
	 *
	 * @return The matching JWKs, empty list if no matches were found or
	 *         retrieval failed.
	 */
	List<JWK> get(final Identifier id, final JWKMatcher jwkMatcher);
}
