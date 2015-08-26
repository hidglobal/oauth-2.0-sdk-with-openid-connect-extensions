package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.token.AccessToken;


/**
 * Access token hash ({@code at_hash}).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.3.6.
 * </ul>
 */
@Immutable
public final class AccessTokenHash extends HashClaim {


	/**
	 * Checks if an access token hash claim must be included in ID tokens
	 * for the specified response type.
	 *
	 * @param responseType The OpenID Connect response type. Must not be
	 *                     {@code null}.
	 *
	 * @return {@code true} if the access token hash is required, else
	 *         {@code false}.
	 */
	public static boolean isRequiredInIDTokenClaims(final ResponseType responseType) {

		// Only required in implicit flow for 'token id_token' and
		// hybrid flow for 'code id_token token'
		// Disregard authz / token endpoint!
		if (    new ResponseType("token", "id_token").equals(responseType) ||
			new ResponseType("code", "id_token", "token").equals(responseType)) {

			return true;
		}

		return false;
	}


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
