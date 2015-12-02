package com.nimbusds.openid.connect.sdk.jwt;


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
import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Selector of client secret keys for verifying HMAC protected JWS objects used
 * in OpenID Connect.
 *
 * <p>Can be used to select key candidates for the verification of:
 *
 * <ul>
 *     <li>HMAC ID tokens.
 *     <li>HMAC JWT-encoded UserInfo responses.
 *     <li>HMAC OpenID request objects.
 * </ul>
 */
@ThreadSafe
public class ClientSecretSelector extends AbstractKeySelector implements JWSKeySelector {


	/**
	 * The expected JWS algorithm.
	 */
	private final JWSAlgorithm jwsAlg;
	

	/**
	 * The client secret.
	 */
	private final SecretKey secretKey;


	/**
	 * Creates a new client secret selector.
	 *
	 * @param id           Identifier for the JWS originator, typically the
	 *                     client ID. Must not be {@code null}.
	 * @param hmacAlg      The expected HMAC JWS algorithm. Must not be
	 *                     {@code null}.
	 * @param clientSecret The client secret. Must be at least 256 bits and
 	 *                     and not {@code null}.
	 */
	public ClientSecretSelector(final Identifier id, final JWSAlgorithm hmacAlg, final Secret clientSecret) {

		super(id);

		if (! JWSAlgorithm.Family.HMAC_SHA.contains(hmacAlg)) {
			throw new IllegalArgumentException("The JWS algorithm must be HMAC based");
		}

		jwsAlg = hmacAlg;

		final byte[] secret = clientSecret.getValueBytes();

		if (ByteUtils.bitLength(secret) < 256) {
			throw new IllegalArgumentException("The secret length must be at least 256 bits");
		}

		this.secretKey = new SecretKeySpec(clientSecret.getValueBytes(), "HMAC");
	}


	/**
	 * Returns the client secret.
	 *
	 * @return The client secret.
	 */
	public Secret getSecret() {

		return new Secret(new String(secretKey.getEncoded(), Charset.forName("UTF-8")));
	}


	@Override
	public List<? extends Key> selectJWSKeys(final JWSHeader header, final SecurityContext context) {

		if (! jwsAlg.equals(header.getAlgorithm())) {
			// Unexpected JWS HMAC alg
			return null;
		}

		return Collections.singletonList(secretKey);
	}
}
