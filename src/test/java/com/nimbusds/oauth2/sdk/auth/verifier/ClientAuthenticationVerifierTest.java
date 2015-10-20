package com.nimbusds.oauth2.sdk.auth.verifier;


import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;


/**
 * Tests the client authentication verifier.
 */
public class ClientAuthenticationVerifierTest extends TestCase {


	private static final ClientID VALID_CLIENT_ID = new ClientID("123");


	private static final Secret VALID_CLIENT_SECRET = new Secret();


	private static final Set<Audience> EXPECTED_JWT_AUDIENCE = new LinkedHashSet<>(Arrays.asList(
		new Audience("https://c2id.com/token"),
		new Audience("https://c2id.com")));


	private static final RSAPrivateKey VALID_RSA_PRIVATE_KEY;


	private static final RSAPrivateKey INVALID_RSA_PRIVATE_KEY;


	private static final RSAPublicKey VALID_RSA_PUBLIC_KEY;


	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			KeyPair keyPair = gen.generateKeyPair();
			VALID_RSA_PRIVATE_KEY = (RSAPrivateKey)keyPair.getPrivate();
			VALID_RSA_PUBLIC_KEY = (RSAPublicKey)keyPair.getPublic();

			// Generate non-matching key to simulate invalid signature
			keyPair = gen.generateKeyPair();
			INVALID_RSA_PRIVATE_KEY = (RSAPrivateKey)keyPair.getPrivate();
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}


	private static final ClientCredentialsSelector<ClientMetadata> CLIENT_CREDENTIALS_SELECTOR = new ClientCredentialsSelector<ClientMetadata>() {


		@Override
		public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context<ClientMetadata> context) {
			assert authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) ||
				authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST) ||
				authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
			if (claimedClientID.equals(VALID_CLIENT_ID)) {
				return Arrays.asList(VALID_CLIENT_SECRET);
			}
			return null;
		}


		@Override
		public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, Context<ClientMetadata> context) {
			assert authMethod.equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
			if (claimedClientID.equals(VALID_CLIENT_ID)) {
				return Arrays.asList(VALID_RSA_PUBLIC_KEY);
			}
			return null;
		}
	};


	public void testGetters() {

		ClientCredentialsSelector selector = new ClientCredentialsSelector() {
			@Override
			public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) {
				return null;
			}


			@Override
			public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, Context context) {
				return null;
			}
		};

		Set<Audience> audienceSet = new HashSet<>();
		audienceSet.add(new Audience("https://c2id.com/token"));

		ClientAuthenticationVerifier verifier = new ClientAuthenticationVerifier(selector, audienceSet);

		assertEquals(selector, verifier.getClientCredentialsSelector());
		assertEquals(audienceSet, verifier.getExpectedAudience());
	}


	private static ClientAuthenticationVerifier<ClientMetadata> createVerifier() {

		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, EXPECTED_JWT_AUDIENCE);
	}


	public void testHappyClientSecretBasic()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		assertTrue(createVerifier().verify(clientAuthentication, null));
	}


	public void testHappyClientSecretPost()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		assertTrue(createVerifier().verify(clientAuthentication, null));
	}


	public void testHappyClientSecretJWT()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		assertTrue(createVerifier().verify(clientAuthentication, null));
	}


	public void testHappyPrivateKeyJWT()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_PRIVATE_KEY,
			null);

		assertTrue(createVerifier().verify(clientAuthentication, null));
	}


	public void testInvalidClientSecretPost()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, new Secret());

		assertFalse(createVerifier().verify(clientAuthentication, null));
	}


	public void testInvalidClientSecretJWTSignature()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			new Secret());

		assertFalse(createVerifier().verify(clientAuthentication, null));
	}


	public void testInvalidPrivateKeyJWTSignature()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_PRIVATE_KEY,
			null);

		assertFalse(createVerifier().verify(clientAuthentication, null));
	}


	public void testClientSecretJWTBadAudience()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://other.com/token"),
			JWSAlgorithm.HS256,
			new Secret());

		assertFalse(createVerifier().verify(clientAuthentication, null));
	}


	public void testPrivateKeyJWTBadAudience()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://other.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_PRIVATE_KEY,
			null);

		assertFalse(createVerifier().verify(clientAuthentication, null));
	}


	public void testExpiredClientSecretJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000l);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			VALID_CLIENT_ID,
			EXPECTED_JWT_AUDIENCE.iterator().next().toSingleAudienceList(),
			before5min,
			null,
			now,
			new JWTID());

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());
		jwt.sign(new MACSigner(VALID_CLIENT_SECRET.getValueBytes()));

		ClientAuthentication clientAuthentication = new ClientSecretJWT(jwt);

		assertFalse(createVerifier().verify(clientAuthentication, null));
	}


	public void testExpiredPrivateKeyJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000l);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			VALID_CLIENT_ID,
			EXPECTED_JWT_AUDIENCE.iterator().next().toSingleAudienceList(),
			before5min,
			null,
			now,
			new JWTID());

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet.toJWTClaimsSet());
		jwt.sign(new RSASSASigner(VALID_RSA_PRIVATE_KEY));

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(jwt);

		assertFalse(createVerifier().verify(clientAuthentication, null));
	}
}
