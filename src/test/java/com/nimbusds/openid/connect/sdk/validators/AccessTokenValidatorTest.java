package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import junit.framework.TestCase;


/**
 * Tests the access token hash validator.
 */
public class AccessTokenValidatorTest extends TestCase {
	

	public void testValid()
		throws InvalidHashException {

		AccessToken token = new BearerAccessToken(32);
		AccessTokenHash atHash = AccessTokenHash.compute(token, JWSAlgorithm.HS256);
		AccessTokenValidator.validate(token, JWSAlgorithm.HS256, atHash);
	}


	public void testUnsupportedAlg() {

		AccessToken token = new BearerAccessToken(32);
		AccessTokenHash atHash = AccessTokenHash.compute(token, JWSAlgorithm.HS256);
		try {
			AccessTokenValidator.validate(token, new JWSAlgorithm("none"), atHash);
			fail();
		} catch (InvalidHashException e) {
			// ok
		}
	}


	public void testInvalidHash() {

		AccessToken token = new BearerAccessToken(32);
		try {
			AccessTokenValidator.validate(token, JWSAlgorithm.HS256, new AccessTokenHash("xxx"));
			fail();
		} catch (InvalidHashException e) {
			// ok
		}
	}
}
