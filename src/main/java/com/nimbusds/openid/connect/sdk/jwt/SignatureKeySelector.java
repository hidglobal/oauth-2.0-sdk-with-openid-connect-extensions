package com.nimbusds.openid.connect.sdk.jwt;


import java.security.Key;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Selector of public RSA and EC keys for verifying JWS signatures used in
 * OpenID Connect.
 *
 * <p>Selects key candidates for verification of:
 *
 * <ul>
 *     <li>Signed ID tokens.
 *     <li>Signed JWT-encoded UserInfo responses.
 *     <li>Signed OpenID request objects.
 * </ul>
 */
@ThreadSafe
public class SignatureKeySelector extends AbstractKeySelectorWithJWKSetSource implements JWSKeySelector {


	/**
	 * The expected JWS algorithm.
	 */
	private final JWSAlgorithm jwsAlg;


	/**
	 * Ensures the specified JWS algorithm is RSA or EC based.
	 *
	 * @param jwsAlg The JWS algorithm to check.
	 */
	private static void ensureSignatureAlgorithm(final JWSAlgorithm jwsAlg) {

		if (! JWSAlgorithm.Family.RSA.contains(jwsAlg) || ! JWSAlgorithm.Family.EC.contains(jwsAlg)) {
			throw new IllegalArgumentException("The JWS algorithm must be RSA or EC based");
		}
	}


	/**
	 * Creates a new signature key selector.
	 *
	 * @param id           Identifier for the JWS author, typically an
	 *                     OpenID Provider issuer ID, or client ID. Must
	 *                     not be {@code null}.
	 * @param jwsAlg       The expected JWS algorithm for the objects to be
	 *                     verified. Must not be {@code null}.
	 * @param jwkSetSource The JWK set source. Must not be {@code null}.
	 */
	public SignatureKeySelector(final Identifier id, final JWSAlgorithm jwsAlg, final JWKSetSource jwkSetSource) {

		super(id, jwkSetSource);
		ensureSignatureAlgorithm(jwsAlg);
		this.jwsAlg = jwsAlg;
	}


	/**
	 * Returns the expected JWS algorithm.
	 *
	 * @return The expected JWS algorithm.
	 */
	public JWSAlgorithm getExpectedJWSAlgorithm() {

		return jwsAlg;
	}


	/**
	 * Creates a JWK matchers for the expected JWS algorithm and the
	 * specified JWS header.
	 *
	 * @param jwsHeader The JWS header. Must not be {@code null}.
	 *
	 * @return The JWK matcher.
	 */
	protected JWKMatcher createJWKMatcher(final JWSHeader jwsHeader) {

		return new JWKMatcher.Builder()
				.keyType(KeyType.forAlgorithm(getExpectedJWSAlgorithm()))
				.keyID(jwsHeader.getKeyID())
				.keyUses(KeyUse.SIGNATURE, null)
				.algorithms(getExpectedJWSAlgorithm(), null)
				.build();
	}


	@Override
	public List<? extends Key> selectJWSKeys(final JWSHeader jwsHeader, final SecurityContext context) {

		JWKMatcher jwkMatcher = createJWKMatcher(jwsHeader);
		List<JWK> jwkMatches = getJWKSetSource().get(getIdentifier(), jwkMatcher);

		// Convert JWKs to Java key types
		List<Key> keyMatches = new LinkedList<>();
		for (JWK jwk: jwkMatches) {
			try {
				if (jwk instanceof RSAKey) {
					keyMatches.add(((RSAKey) jwk).toRSAPublicKey());
				} else if (jwk instanceof ECKey) {
					keyMatches.add(((ECKey) jwk).toECPublicKey());
				}
			} catch (JOSEException e) {
				// ignore and continue
			}
		}
		return keyMatches;
	}
}
