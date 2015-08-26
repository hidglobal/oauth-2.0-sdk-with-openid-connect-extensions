package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;


/**
 * Authorisation code hash ({@code c_hash}).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.3.2.11.
 * </ul>
 */
@Immutable
public final class CodeHash extends HashClaim {


	/**
	 * Checks if an authorisation code hash claim must be included in ID
	 * tokens for the specified response type.
	 *
	 * @param responseType The he OpenID Connect response type. Must not be
	 *                     {@code null}.
	 *
	 * @return {@code true} if the code hash is required, else
	 *         {@code false}.
	 */
	public static boolean isRequiredInIDTokenClaims(final ResponseType responseType) {

		// Only required in hybrid flow for 'code id_token' and 'code id_token token'
		// Disregard authz / token endpoint!
		if (    new ResponseType("code", "id_token").equals(responseType) ||
			new ResponseType("code", "id_token", "token").equals(responseType)) {

			return true;
		}

		return false;
	}


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
