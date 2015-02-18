package com.nimbusds.openid.connect.sdk;


import javax.mail.internet.InternetAddress;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Subject;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;


/**
 * Tests the UserInfo success response.
 */
public class UserInfoSuccessResponseTest extends TestCase {


	public void testPlain()
		throws Exception {

		UserInfo claims = new UserInfo(new Subject("alice"));
		claims.setName("Alice Adams");
		claims.setEmail(new InternetAddress("alice@wonderland.net"));
		claims.setEmailVerified(true);

		UserInfoSuccessResponse response = new UserInfoSuccessResponse(claims);

		assertTrue(response.indicatesSuccess());
		assertEquals("application/json; charset=UTF-8", response.getContentType().toString());
		assertNull(response.getUserInfoJWT());
		assertEquals(claims, response.getUserInfo());
		HTTPResponse httpResponse = response.toHTTPResponse();

		response = UserInfoSuccessResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals("application/json; charset=UTF-8", response.getContentType().toString());
		assertNull(response.getUserInfoJWT());

		claims = response.getUserInfo();

		assertEquals("alice", claims.getSubject().getValue());
		assertEquals("Alice Adams", claims.getName());
		assertEquals("alice@wonderland.net", claims.getEmail().toString());
		assertTrue(claims.getEmailVerified());
	}


	public void testJWT()
		throws Exception {

		UserInfo claims = new UserInfo(new Subject("alice"));
		claims.setName("Alice Adams");
		claims.setEmail(new InternetAddress("alice@wonderland.net"));
		claims.setEmailVerified(true);

		JWTClaimsSet claimsSet = claims.toJWTClaimsSet();

		Secret secret = new Secret();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		jwt.sign(new MACSigner(secret.getValueBytes()));

		UserInfoSuccessResponse response = new UserInfoSuccessResponse(jwt);

		assertTrue(response.indicatesSuccess());
		assertEquals(jwt, response.getUserInfoJWT());
		assertEquals("application/jwt; charset=UTF-8", response.getContentType().toString());
		assertNull(response.getUserInfo());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = UserInfoSuccessResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals("application/jwt; charset=UTF-8", response.getContentType().toString());
		assertNull(response.getUserInfo());

		jwt = (SignedJWT)response.getUserInfoJWT();

		assertTrue(jwt.getState().equals(JWSObject.State.SIGNED));

		claims = new UserInfo(response.getUserInfoJWT().getJWTClaimsSet().toJSONObject());

		assertEquals("alice", claims.getSubject().getValue());
		assertEquals("Alice Adams", claims.getName());
		assertEquals("alice@wonderland.net", claims.getEmail().toString());
		assertTrue(claims.getEmailVerified());
	}
}
