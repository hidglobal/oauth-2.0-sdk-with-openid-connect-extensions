package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import net.jcip.annotations.ThreadSafe;


/**
 * Authorisation code validator, using the {@code c_hash} ID token claim.
 * Required in the hybrid flow where the authorisation code is returned
 * together with an ID token at the authorisation endpoint.
 */
@ThreadSafe
public class AuthorizationCodeValidator {
	

	/**
	 * Validates the specified authorisation code.
	 *
	 * @param code         The authorisation code. Must not be
	 *                     {@code null}.
	 * @param jwsAlgorithm The JWS algorithm of the ID token. Must not
	 *                     be {@code null}.=
	 * @param codeHash     The authorisation code hash, as set in the
	 *                     {@code c_hash} ID token claim. Must not be
	 *                     {@code null}.
	 *
	 * @throws InvalidHashException If the authorisation code doesn't match
	 *                              the hash.
	 */
	public static void validate(final AuthorizationCode code,
				    final JWSAlgorithm jwsAlgorithm,
				    final CodeHash codeHash)
		throws InvalidHashException {

		CodeHash expectedHash = CodeHash.compute(code, jwsAlgorithm);

		if (expectedHash == null) {
			throw InvalidHashException.INVALID_CODE_HASH_EXCEPTION;
		}

		if (! expectedHash.equals(codeHash)) {
			throw InvalidHashException.INVALID_CODE_HASH_EXCEPTION;
		}
	}
}
