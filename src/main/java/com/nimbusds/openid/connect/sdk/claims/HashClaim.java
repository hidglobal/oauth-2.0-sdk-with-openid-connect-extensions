package com.nimbusds.openid.connect.sdk.claims;


import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * The base class for SHA-2 based claims.
 *
 * @author Vladimir Dzhuvinov
 */
public abstract class HashClaim extends Identifier {


	/**
	 * Creates a new SHA-2 based claim with the specified value.
	 *
	 * @param value The claim value. Must not be {@code null}.
	 */
	protected HashClaim(final String value) {

		super(value);
	}


	/**
	 * Gets the matching SHA-2 message digest for the specified JSON Web
	 * Signature (JWS) algorithm.
	 *
	 * @param alg The JWS algorithm. Must not be {@code null}.
	 *
	 * @return The SHA-2 message digest, {@code null} if the JWS algorithm
	 *         or its corresponding SHA-2 message digest are not supported.
	 */
	public static MessageDigest getMessageDigestInstance(final JWSAlgorithm alg) {

		String mdAlg;

		if (alg.equals(JWSAlgorithm.HS256) ||
		    alg.equals(JWSAlgorithm.RS256) ||
		    alg.equals(JWSAlgorithm.ES256) ||
		    alg.equals(JWSAlgorithm.PS256)    ) {

			mdAlg = "SHA-256";

		} else if (alg.equals(JWSAlgorithm.HS384) ||
			   alg.equals(JWSAlgorithm.RS384) ||
			   alg.equals(JWSAlgorithm.ES384) ||
			   alg.equals(JWSAlgorithm.PS384)    ) {

			mdAlg = "SHA-384";

		} else if (alg.equals(JWSAlgorithm.HS512) ||
			   alg.equals(JWSAlgorithm.RS512) ||
			   alg.equals(JWSAlgorithm.ES512) ||
			   alg.equals(JWSAlgorithm.PS512)    ) {

			mdAlg = "SHA-512";

		} else {
			// unsupported JWS alg
			return null;
		}

		try {
			return MessageDigest.getInstance(mdAlg);

		} catch (NoSuchAlgorithmException e) {

			// unsupported SHA-2 alg
			return null;
		}
	}


	/**
	 * Computes the SHA-2 claim value for the specified identifier.
	 *
	 * @param identifier The identifier, typically an authorisation code or
	 *                   an access token.  Must not be {@code null}.
	 * @param alg        The reference JSON Web Signature (JWS) algorithm.
	 *                   Must not be {@code null}.
	 *
	 * @return The matching (truncated to first half) SHA-2 claim value,
	 *         or {@code null} if the JWS algorithm or its corresponding
	 *         SHA-2 message digest are not supported.
	 */
	public static String computeValue(final Identifier identifier, final JWSAlgorithm alg) {

		MessageDigest md = getMessageDigestInstance(alg);

		if (md == null)
			return null;

		md.update(identifier.getValue().getBytes(Charset.forName("US-ASCII")));

		byte[] hash = md.digest();

		byte[] firstHalf = Arrays.copyOf(hash, hash.length / 2);

		return Base64.encodeBase64URLSafeString(firstHalf);
	}
}
