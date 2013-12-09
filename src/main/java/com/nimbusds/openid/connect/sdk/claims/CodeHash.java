package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.AuthorizationCode;


/**
 * Authorisation code hash ({@code c_hash}). This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 * </ul>
 */
@Immutable
public final class CodeHash extends HashClaim {


	/**
	 * Creates a new authorisation code hash with the specified value.
	 *
	 * @param value The authorisation code hash value. Must not be 
	 *              {@code null}.
	 */
	public CodeHash(final String value) {
	
		super(value);
	}


	/**
	 * Computes the hash for the specified authorisation code and reference
	 * JSON Web Signature (JWS) algorithm.
	 *
	 * @param code The authorisation code. Must not be {@code null}.
	 * @param alg  The reference JWS algorithm. Must not be {@code null}.
	 *
	 * @return The authorisation code hash, or {@code null} if the JWS
	 *         algorithm is not supported.
	 */
	public static CodeHash compute(final AuthorizationCode code, final JWSAlgorithm alg) {

		String value = computeValue(code, alg);

		if (value == null)
			return null;

		return new CodeHash(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof CodeHash &&
		       this.toString().equals(object.toString());
	}
}
