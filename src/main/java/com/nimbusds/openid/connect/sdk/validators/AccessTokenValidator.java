package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import net.jcip.annotations.ThreadSafe;


/**
 * Access token validator, using the {@code at_hash} ID token claim. Required
 * in the implicit flow and the hybrid flow where the access token is returned
 * at the authorisation endpoint.
 */
@ThreadSafe
public class AccessTokenValidator {
	

	/**
	 * Validates the specified access token.
	 *
	 * @param accessToken     The access token. Must not be {@code null}.
	 * @param jwsAlgorithm    The JWS algorithm of the ID token. Must not
	 *                        be {@code null}.
	 * @param accessTokenHash The access token hash, as set in the
	 *                        {@code at_hash} ID token claim. Must not be
	 *                        {@code null},
	 *
	 * @throws InvalidHashException If the access token doesn't match the
	 *                              hash.
	 */
	public static void validate(final AccessToken accessToken,
				    final JWSAlgorithm jwsAlgorithm,
				    final AccessTokenHash accessTokenHash)
		throws InvalidHashException {

		AccessTokenHash expectedHash = AccessTokenHash.compute(accessToken, jwsAlgorithm);

		if (expectedHash == null) {
			throw InvalidHashException.INVALID_ACCESS_T0KEN_HASH_EXCEPTION;
		}

		if (! expectedHash.equals(accessTokenHash)) {
			throw InvalidHashException.INVALID_ACCESS_T0KEN_HASH_EXCEPTION;
		}
	}
}
