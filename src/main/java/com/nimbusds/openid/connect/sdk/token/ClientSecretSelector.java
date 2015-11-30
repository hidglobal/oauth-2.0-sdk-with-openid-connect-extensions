package com.nimbusds.openid.connect.sdk.token;


import java.nio.charset.Charset;
import java.security.Key;
import java.util.Collections;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.auth.Secret;


/**
 * Singleton client secret selector for JWS HMAC verification.
 */
public class ClientSecretSelector implements JWSKeySelector {
	

	/**
	 * The client secret.
	 */
	private final SecretKey secretKey;


	/**
	 * The expected HMAC JWS algorithm, {@code null} if not specified.
	 */
	private final JWSAlgorithm hmacAlg;


	/**
	 * Creates a new client secret selector.
	 *
	 * @param clientSecret The client secret. Must be at least 256 bits and
	 *                     and not {@code null}.
	 * @param hmacAlg      The expected HMAC JWS algorithm, {@code null} if
	 *                     not specified.
	 */
	public ClientSecretSelector(final Secret clientSecret, final JWSAlgorithm hmacAlg) {

		final byte[] secret = clientSecret.getValueBytes();

		if (ByteUtils.bitLength(secret) < 256) {
			throw new IllegalArgumentException("The secret length must be at least 256 bits");
		}

		this.secretKey = new SecretKeySpec(clientSecret.getValueBytes(), "HMAC");

		this.hmacAlg = hmacAlg;
	}


	public Secret getSecret() {

		return new Secret(new String(secretKey.getEncoded(), Charset.forName("UTF-8")));
	}


	@Override
	public List<? extends Key> selectJWSKeys(final JWSHeader header, final SecurityContext context) {

		if (! JWSAlgorithm.Family.HMAC_SHA.contains(header.getAlgorithm())) {
			return null; // JWS alg must be HMAC
		}

		return Collections.singletonList(secretKey);
	}
}
