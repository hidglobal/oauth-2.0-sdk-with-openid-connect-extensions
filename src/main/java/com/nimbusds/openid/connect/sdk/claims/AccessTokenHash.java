package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.token.AccessToken;


/**
 * Access token hash ({@code at_hash}). This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 * </ul>
 */
@Immutable
public final class AccessTokenHash extends HashClaim {


	/**
	 * Creates a new access token hash with the specified value.
	 *
	 * @param value The access token hash value. Must not be {@code null}.
	 */
	public AccessTokenHash(final String value) {
	
		super(value);
	}


	/**
	 * Computes the hash for the specified access token and reference JSON
	 * Web Signature (JWS) algorithm.
	 *
	 * @param accessToken The access token. Must not be {@code null}.
	 * @param alg         The reference JWS algorithm. Must not be
	 *                    {@code null}.
	 *
	 * @return The access token hash, or {@code null} if the JWS algorithm
	 *         is not supported.
	 */
	public static AccessTokenHash compute(final AccessToken accessToken, final JWSAlgorithm alg) {

		String value = computeValue(accessToken, alg);

		if (value == null)
			return null;

		return new AccessTokenHash(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AccessTokenHash &&
		       this.toString().equals(object.toString());
	}
}
