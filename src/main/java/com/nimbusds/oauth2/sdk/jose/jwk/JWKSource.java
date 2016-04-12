package com.nimbusds.oauth2.sdk.jose.jwk;


import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * JSON Web Key (JWK) source. Exposes a method for retrieving selected keys for
 * a party (OAuth 2.0 server or client). Implementations must be thread-safe.
 */
@Deprecated
public interface JWKSource {
	

	/**
	 * Retrieves a list of JWKs matching the specified criteria.
	 *
	 * @param id          Identifier of the JWK owner, typically an
	 *                    Authorisation Server / OpenID Provider issuer ID,
	 *                    or client ID. Must not be {@code null}.
	 * @param jwkSelector A JWK selector. Must not be {@code null}.
	 *
	 * @return The matching JWKs, empty list if no matches were found or
	 *         retrieval failed.
	 */
	List<JWK> get(final Identifier id, final JWKSelector jwkSelector);
}
