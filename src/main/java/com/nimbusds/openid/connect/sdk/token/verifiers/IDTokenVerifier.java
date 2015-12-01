package com.nimbusds.openid.connect.sdk.token.verifiers;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.jwt.ClientSecretSelector;
import com.nimbusds.openid.connect.sdk.jwt.JWKSetSource;
import com.nimbusds.openid.connect.sdk.jwt.SignatureKeySelector;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import net.jcip.annotations.ThreadSafe;


/**
 * Verifier of ID tokens issued by an OpenID Provider (OP).
 *
 * <p>Supported ID tokens:
 *
 * <ul>
 *     <li>ID tokens signed (JWS) with the OP's RSA or EC key, require the
 *         OP public JWK set (provided by value or URL) to verify them.
 *     <li>ID tokens authenticated with a JWS HMAC, require the client's secret
 *         to verify them.
 *     <li>Unsecured (plain) ID tokens received
 *
 * </ul>
 */
@ThreadSafe
public class IDTokenVerifier {


	/**
	 * The expected ID token issuer.
	 */
	private final Issuer expectedIssuer;


	/**
	 * The requesting client.
	 */
	private final ClientID clientID;


	/**
	 * The JWS key selector.
	 */
	private final JWSKeySelector jwsKeySelector;


	/**
	 * The JWE key selector.
	 */
	private final JWEKeySelector jweKeySelector;


	/**
	 * Creates a new verifier for unsecured (plain) ID tokens.
	 *
	 * @param expectedIssuer
	 * @param clientID
	 */
	public IDTokenVerifier(final Issuer expectedIssuer,
			       final ClientID clientID) {

		this(expectedIssuer, clientID, (JWSKeySelector) null, (JWEKeySelector) null);
	}


	/**
	 * Creates a new verifier for RSA or EC signed ID tokens.
	 *
	 * @param expectedIssuer
	 * @param clientID
	 * @param expectedJWSAlg
	 * @param jwkSetSource
	 */
	public IDTokenVerifier(final Issuer expectedIssuer,
			       final ClientID clientID,
			       final JWSAlgorithm expectedJWSAlg,
			       final JWKSetSource jwkSetSource) {

		this(expectedIssuer, clientID, new SignatureKeySelector(expectedIssuer, expectedJWSAlg, jwkSetSource),  null);
	}


	/**
	 * Creates a new verifier for HMAC protected ID tokens.
	 *
	 * @param expectedIssuer
	 * @param clientID
	 * @param expectedJWSAlg
	 * @param clientSecret
	 */
	public IDTokenVerifier(final Issuer expectedIssuer,
			       final ClientID clientID,
			       final JWSAlgorithm expectedJWSAlg,
			       final Secret clientSecret) {

		this(expectedIssuer, clientID, new ClientSecretSelector(expectedIssuer, expectedJWSAlg, clientSecret), null);
	}


	/**
	 * Creates a new ID token verifier.
	 *
	 * @param expectedIssuer
	 * @param clientID
	 * @param jwsKeySelector
	 */
	public IDTokenVerifier(final Issuer expectedIssuer,
			       final ClientID clientID,
			       final JWSKeySelector jwsKeySelector,
			       final JWEKeySelector jweKeySelector) {
		this.expectedIssuer = expectedIssuer;
		this.clientID = clientID;
		this.jwsKeySelector = jwsKeySelector;
		this.jweKeySelector = jweKeySelector;
	}


	/**
	 * Returns the expected ID token issuer.
	 *
	 * @return The ID token issuer.
	 */
	public Issuer getExpectedIssuer() {
		return expectedIssuer;
	}


	/**
	 * Returns the client ID (the expected ID token audience).
	 *
	 * @return The client ID.
	 */
	public ClientID getClientID() {
		return clientID;
	}


	/**
	 * Returns the configured JWS key selector for signed ID token
	 * verification.
	 *
	 * @return The JWS key selector, {@code null} if none.
	 */
	public JWSKeySelector getJWSKeySelector() {
		return jwsKeySelector;
	}


	/**
	 * Returns the configured JWE key selector for encrypted ID token
	 * decryption.
	 *
	 * @return The JWE key selector, {@code null}.
	 */
	public JWEKeySelector getJWEKeySelector() {
		return jweKeySelector;
	}


	public IDTokenClaimsSet verify(final JWT idToken, final Nonce expectedNonce, final boolean viaHTTPS)
		throws BadJOSEException, JOSEException {

		if (idToken instanceof SignedJWT) {
			return verify((SignedJWT) idToken, expectedNonce, viaHTTPS);

		}

		return null;
	}


	private IDTokenClaimsSet verify(final SignedJWT idToken, final Nonce expectedNonce, final boolean viaHTTPS)
		throws BadJOSEException, JOSEException {

		if (jwsKeySelector == null) {
			throw new BadJWTException("Verification of signed JWTs not configured");
		}

		ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWSKeySelector(jwsKeySelector);
		jwtProcessor.setJWTClaimsVerifier(new IDTokenClaimsVerifier(expectedIssuer, clientID, expectedNonce));

		JWTClaimsSet jwtClaimsSet = jwtProcessor.process(idToken, null);

		try {
			return new IDTokenClaimsSet(jwtClaimsSet);
		} catch (ParseException e) {
			// Claims set must be verified at this point
			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Creates a new ID token verifier for the specified OpenID Provider
	 * metadata and OpenID Relying Party registration.
	 *
	 * @param opMetadata The OpenID Provider metadata. Must not be
	 *                   {@code null}.
	 * @param clientInfo The OpenID Relying Party registration. Must not be
	 *                   {@code null}.
	 *
	 * @return The ID token verifier.
	 */
	public static IDTokenVerifier create(final OIDCProviderMetadata opMetadata,
					     final OIDCClientInformation clientInfo) {

		Issuer expectedIssuer = opMetadata.getIssuer();
		ClientID expectedClientID = clientInfo.getID();

		JWSAlgorithm expectedJWSAlgorithm = clientInfo.getOIDCMetadata().getIDTokenJWSAlg();

		if (Algorithm.NONE.equals(expectedJWSAlgorithm)) {

			return null;
		} else if (JWSAlgorithm.Family.RSA.contains(expectedJWSAlgorithm) || JWSAlgorithm.Family.EC.contains(expectedJWSAlgorithm)) {

			return null;
		} else if (JWSAlgorithm.Family.HMAC_SHA.contains(expectedJWSAlgorithm)) {

			return null;
		} else {
			return null;
		}
	}
}
