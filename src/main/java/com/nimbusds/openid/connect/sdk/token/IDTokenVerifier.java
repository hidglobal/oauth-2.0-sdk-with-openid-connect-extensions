package com.nimbusds.openid.connect.sdk.token;


import java.net.URL;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
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


	public class Builder {





		public Builder(final Issuer expectedIssuer, final ClientID expectedClientID) {

			if (expectedIssuer == null) {
				throw new IllegalArgumentException("The expected issuer must not be null");
			}
			this.expectedIssuer = expectedIssuer;

			if (expectedClientID == null) {
				throw new IllegalArgumentException("The expected client ID must not be null");
			}
			this.expectedClientID = expectedClientID;
		}


		public Builder forPlainIDTokens() {

			jwtProcessor = null;
			return this;
		}


		public Builder forOPSignedIDTokens(final URL jwkSetURL) {

			return null;
		}


		public Builder forOPSignedIDTokens(final JWKSet jwkSet) {


		}


		public Builder forMACID
	}


	/**
	 * The expected ID token issuer.
	 */
	private final Issuer expectedIssuer;


	/**
	 * The requesting client.
	 */
	private final ClientID expectedClientID;


	/**
	 * The JWT processor.
	 */
	private JWTProcessor jwtProcessor;


	/**
	 * The JWT verifier.
	 */
	private DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor();


	public IDTokenVerifier(final Issuer expectedIssuer,
			       final ClientID  expectedClientID,
			       )


	public IDTokenVerifier(final JWSAlgorithm hmacJWSAlg, final Secret clientSecret) {


	}


	public IDTokenClaimsSet verify(final JWT idToken, final boolean viaHTTPS) {

		return null;
	}
}
