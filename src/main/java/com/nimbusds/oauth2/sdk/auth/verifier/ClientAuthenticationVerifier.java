package com.nimbusds.oauth2.sdk.auth.verifier;


import java.security.PublicKey;
import java.util.List;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;

import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.id.Audience;


/**
 * Client authentication verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 2.3.1 and 3.2.1.
 *     <li>OpenID Connect Core 1.0, section 9.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
@ThreadSafe
public class ClientAuthenticationVerifier<T> {


	/**
	 * The client credentials selector.
	 */
	private final ClientCredentialsSelector<T> clientCredentialsSelector;


	/**
	 * The JWT assertion claims set verifier.
	 */
	private final JWTAuthenticationClaimsSetVerifier claimsSetVerifier;


	/**
	 * JWS verifier factory for private_key_jwt authentication.
	 */
	private final JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();


	/**
	 * Creates a new client authentication verifier.
	 *
	 * @param clientCredentialsSelector The client credentials selector.
	 *                                  Must not be {@code null}.
	 * @param expectedAudience          The permitted audience (aud) claim
	 *                                  values in JWT authentication
	 *                                  assertions. Must not be empty or
	 *                                  {@code null}. Should typically
	 *                                  contain the token endpoint URI and
	 *                                  for OpenID provider it may also
	 *                                  include the issuer URI.
	 */
	public ClientAuthenticationVerifier(final ClientCredentialsSelector<T> clientCredentialsSelector,
					    final Set<Audience> expectedAudience) {

		claimsSetVerifier = new JWTAuthenticationClaimsSetVerifier(expectedAudience);

		if (clientCredentialsSelector == null) {
			throw new IllegalArgumentException("The client credentials selector must not be null");
		}

		this.clientCredentialsSelector = clientCredentialsSelector;
	}


	/**
	 * Returns the client credentials selector.
	 *
	 * @return The client credentials selector.
	 */
	public ClientCredentialsSelector<T> getClientCredentialsSelector() {

		return clientCredentialsSelector;
	}


	/**
	 * Returns the permitted audience values in JWT authentication
	 * assertions.
	 *
	 * @return The permitted audience (aud) claim values.
	 */
	public Set<Audience> getExpectedAudience() {

		return claimsSetVerifier.getExpectedAudience();
	}


	/**
	 * Verifies a client authentication request.
	 *
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param context    Additional context to be passed to the client
	 *                   credentials selector. May be {@code null}.
	 *
	 * @return {@code true} if the client was successfully authenticated,
	 *         {@code false} if the authentication failed due to an unknown
	 *         client, invalid credential or unsupported authentication
	 *         method.
	 *
	 * @throws JOSEException
	 */
	public boolean verify(final ClientAuthentication clientAuth, final Context<T> context)
		throws JOSEException {

		if (clientAuth instanceof PlainClientSecret) {

			List<Secret> secretCandidates = clientCredentialsSelector.selectClientSecrets(
				clientAuth.getClientID(),
				clientAuth.getMethod(),
				context);

			if (secretCandidates == null) {
				return false; // invalid client
			}

			PlainClientSecret plainAuth = (PlainClientSecret)clientAuth;

			for (Secret candidate: secretCandidates) {
				if (plainAuth.getClientSecret().equals(candidate)) {
					return true; // success
				}
			}

			return false; // invalid client

		} else if (clientAuth instanceof ClientSecretJWT) {

			ClientSecretJWT jwtAuth = (ClientSecretJWT) clientAuth;

			// Check claims first before calling backend
			try {
				claimsSetVerifier.verify(jwtAuth.getJWTAuthenticationClaimsSet().toJWTClaimsSet());
			} catch (BadJWTException e) {
				return false; // invalid client
			}

			List<Secret> secretCandidates = clientCredentialsSelector.selectClientSecrets(
				clientAuth.getClientID(),
				clientAuth.getMethod(),
				context);

			if (secretCandidates == null) {
				return false; // invalid client
			}

			SignedJWT assertion = jwtAuth.getClientAssertion();

			for (Secret candidate : secretCandidates) {

				boolean valid = assertion.verify(new MACVerifier(candidate.getValueBytes()));

				if (valid) {
					return true; // success
				}
			}

			return false; // invalid client

		} else if (clientAuth instanceof PrivateKeyJWT) {

			PrivateKeyJWT jwtAuth = (PrivateKeyJWT)clientAuth;

			// Check claims first before calling backend
			try {
				claimsSetVerifier.verify(jwtAuth.getJWTAuthenticationClaimsSet().toJWTClaimsSet());
			} catch (BadJWTException e) {
				return false; // invalid client
			}

			List<? extends PublicKey> keyCandidates = clientCredentialsSelector.selectPublicKeys(
				jwtAuth.getClientID(),
				jwtAuth.getMethod(),
				jwtAuth.getClientAssertion().getHeader(),
				context);

			if  (keyCandidates == null) {
				return false; // invalid client
			}

			SignedJWT assertion = jwtAuth.getClientAssertion();

			for (PublicKey candidate: keyCandidates) {

				if (candidate == null) {
					continue; // skip
				}

				JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(
					jwtAuth.getClientAssertion().getHeader(),
					candidate);

				boolean valid = assertion.verify(jwsVerifier);

				if (valid) {
					return true; // success
				}
			}

			return false; // invalid client

		} else {
			throw new RuntimeException("Unexpected client authentication: " + clientAuth.getMethod());
		}
	}
}
