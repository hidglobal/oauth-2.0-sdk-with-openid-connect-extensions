package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;


/**
 * Tests the logout request class.
 */
public class LogoutRequestTest extends TestCase {


	public void testMinimalConstructor()
		throws Exception {

		Issuer iss = new Issuer("https://c2id.com");
		Subject sub = new Subject("alice");
		List<Audience> audList = Arrays.asList(new Audience("123"));
		Date exp = new Date(2000l);
		Date iat = new Date(1000l);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

		PlainJWT idToken = new PlainJWT(claimsSet.toJWTClaimsSet());

		URI endpoint = new URI("https://c2id.com/logout");

		LogoutRequest request = new LogoutRequest(endpoint, idToken);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(idToken, request.getIDTokenHint());
		assertNull(request.getPostLogoutRedirectionURI());
		assertNull(request.getState());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());

		request = LogoutRequest.parse(httpRequest);

		assertEquals(Algorithm.NONE, request.getIDTokenHint().getHeader().getAlgorithm());
		assertEquals(iss.getValue(), request.getIDTokenHint().getJWTClaimsSet().getIssuer());
		assertEquals(sub.getValue(), request.getIDTokenHint().getJWTClaimsSet().getSubject());
		assertEquals(audList.get(0).getValue(), request.getIDTokenHint().getJWTClaimsSet().getAudience().get(0));
		assertEquals(exp, request.getIDTokenHint().getJWTClaimsSet().getExpirationTime());
		assertEquals(iat, request.getIDTokenHint().getJWTClaimsSet().getIssueTime());
		assertNull(request.getPostLogoutRedirectionURI());
		assertNull(request.getState());
	}


	public void testFullConstructor()
		throws Exception {

		Issuer iss = new Issuer("https://c2id.com");
		Subject sub = new Subject("alice");
		List<Audience> audList = Arrays.asList(new Audience("123"));
		Date exp = new Date(2000l);
		Date iat = new Date(1000l);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());
		JWSSigner signer = new MACSigner("0123456789abcdef");
		idToken.sign(signer);

		URI postLogoutRedirectURI = new URI("https://client.com/post-logout");
		State state = new State();

		URI endpoint = new URI("https://c2id.com/logout");

		LogoutRequest request = new LogoutRequest(endpoint, idToken, postLogoutRedirectURI, state);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(idToken, request.getIDTokenHint());
		assertEquals(postLogoutRedirectURI, request.getPostLogoutRedirectionURI());
		assertEquals(state, request.getState());

		Map<String,String> params = request.toParameters();
		assertEquals(idToken.serialize(), params.get("id_token_hint"));
		assertEquals(postLogoutRedirectURI.toString(), params.get("post_logout_redirect_uri"));
		assertEquals(state.getValue(), params.get("state"));
		assertEquals(3, params.size());

		URI outputURI = request.toURI();

		assertTrue(outputURI.toString().startsWith("https://c2id.com/logout"));
		params = URLUtils.parseParameters(outputURI.getQuery());
		assertEquals(idToken.serialize(), params.get("id_token_hint"));
		assertEquals(postLogoutRedirectURI.toString(), params.get("post_logout_redirect_uri"));
		assertEquals(state.getValue(), params.get("state"));
		assertEquals(3, params.size());

		request = LogoutRequest.parse(outputURI);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(idToken.serialize(), request.getIDTokenHint().serialize());
		assertEquals(postLogoutRedirectURI, request.getPostLogoutRedirectionURI());
		assertEquals(state, request.getState());
	}


	public void testRejectUnsignedIDToken()
		throws Exception {

		Issuer iss = new Issuer("https://c2id.com");
		Subject sub = new Subject("alice");
		List<Audience> audList = Arrays.asList(new Audience("123"));
		Date exp = new Date(2000l);
		Date iat = new Date(1000l);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());

		URI postLogoutRedirectURI = new URI("https://client.com/post-logout");

		URI endpoint = new URI("https://c2id.com/logout");

		try {
			new LogoutRequest(endpoint, idToken, postLogoutRedirectURI, null).toQueryString();
			fail();
		} catch (SerializeException e) {
			// ok
		}
	}


	public void testRejectStateWithoutRedirectionURI()
		throws Exception {

		Issuer iss = new Issuer("https://c2id.com");
		Subject sub = new Subject("alice");
		List<Audience> audList = Arrays.asList(new Audience("123"));
		Date exp = new Date(2000l);
		Date iat = new Date(1000l);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());

		URI endpoint = new URI("https://c2id.com/logout");

		try {
			new LogoutRequest(endpoint, idToken, null, new State());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The state parameter required a post-logout redirection URI", e.getMessage());
		}
	}


	public void testMissingIDTokenHint()
		throws Exception {

		try {
			new LogoutRequest(new URI("https://c2id.com/logout"), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ID token hint must not be null", e.getMessage());
		}
	}
}
