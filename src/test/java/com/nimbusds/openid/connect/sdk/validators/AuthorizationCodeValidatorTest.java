package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import junit.framework.TestCase;


/**
 * Tests the code validator.
 */
public class AuthorizationCodeValidatorTest extends TestCase {
	

	public void testSuccess()
		throws InvalidHashException {

		AuthorizationCode code = new AuthorizationCode(16);
		CodeHash codeHash = CodeHash.compute(code, JWSAlgorithm.RS256);
		AuthorizationCodeValidator.validate(code, JWSAlgorithm.RS256, codeHash);
	}


	public void testUnsupportedAlg() {

		AuthorizationCode code = new AuthorizationCode(16);
		CodeHash codeHash = CodeHash.compute(code, JWSAlgorithm.RS256);
		try {
			AuthorizationCodeValidator.validate(code, new JWSAlgorithm("none"), codeHash);
			fail();
		} catch (InvalidHashException e) {
			// ok
		}
	}


	public void testInvalidHash() {

		AuthorizationCode code = new AuthorizationCode(16);
		try {
			AuthorizationCodeValidator.validate(code, JWSAlgorithm.RS256, new CodeHash("xxx"));
			fail();
		} catch (InvalidHashException e) {
			// ok
		}
	}
}
