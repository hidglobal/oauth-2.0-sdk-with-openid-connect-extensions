package com.nimbusds.openid.connect.messages;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWSException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.claims.ClientID;


/**
 * Tests authorisation request serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.2 (2012-05-29)
 */
public class AuthorizationRequestTest extends TestCase {
	
	
	public void testSerializeSimple() {
	
		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);
		rts.add(ResponseType.ID_TOKEN);
		
		Scope scope = new Scope();
		scope.add(StdScopeToken.OPENID);
		
		ClientID clientID = new ClientID();
		clientID.setClaimValue("s6BhdRkqt3");
		
		URL redirectURI = null;
		
		try {
			redirectURI = new URL("https://client.example.com/cb");
		
		} catch (MalformedURLException e) {
		
			fail(e.getMessage());
		}
		
		Nonce nonce = new Nonce("n-0S6_WzA2Mj");
		
		AuthorizationRequest authReq = new AuthorizationRequest(
			rts, scope, clientID, redirectURI, nonce);
		
		State state = new State("af0ifjsldkj");
		authReq.setState(state);
		
		String queryString = null;
		
		try {
			queryString = authReq.toQueryString();
		
		} catch (SerializeException e) {
			
			fail(e.getMessage());
		}
		
		System.out.println(queryString);
		
		
		assertEquals(2, authReq.getResponseTypeSet().size());
		assertTrue(authReq.getResponseTypeSet().contains(ResponseType.CODE));
		assertTrue(authReq.getResponseTypeSet().contains(ResponseType.ID_TOKEN));
		
		assertEquals(1, authReq.getScope().size());
		assertTrue(authReq.getScope().contains(StdScopeToken.OPENID));
		
		assertEquals("s6BhdRkqt3", authReq.getClientID().getClaimValue());
		
		assertEquals("https://client.example.com/cb", authReq.getRedirectURI().toString());
		
		assertEquals("n-0S6_WzA2Mj", authReq.getNonce().toString());
		
		assertEquals("af0ifjsldkj", authReq.getState().toString());
	}
	
	
	public void testParseSimple() {
	
		String query = "response_type=code%20id_token" +
			       "&client_id=s6BhdRkqt3" +
			       "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			       "&scope=openid" +
			       "&nonce=n-0S6_WzA2Mj" +
			       "&state=af0ifjsldkj";
		
		AuthorizationRequest req = null;
		
		try {
			req = AuthorizationRequest.parse(query);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		ResponseTypeSet rts = req.getResponseTypeSet();
		assertNotNull(rts);
		assertTrue(rts.contains(ResponseType.CODE));
		assertTrue(rts.contains(ResponseType.ID_TOKEN));
		assertEquals(2, rts.size());
		
		assertEquals("s6BhdRkqt3", req.getClientID().getClaimValue());
		
		assertEquals("https://client.example.com/cb", req.getRedirectURI().toString());
		
		Scope scope = req.getScope();
		assertNotNull(scope);
		assertTrue(scope.contains(StdScopeToken.OPENID));
		assertEquals(1, scope.size());
		
		assertEquals(new Nonce("n-0S6_WzA2Mj"), req.getNonce());
		
		assertEquals(new State("af0ifjsldkj"), req.getState());
	}
	
	
	public void testParseWithRequestObject() {
	
		// See http://openid.net/specs/openid-connect-standard-1_0.html#req_param_method
	
		String query = "response_type=code%20id_token" +
		               "&client_id=s6BhdRkqt3" +
			       "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			       "&scope=openid" +
			       "&state=af0ifjsldkj" +
			       "&nonce=n-0S6_WzA2Mj" +
			       "&request=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoiY2" +
			       "9kZSBpZF90b2tlbiIsImNsaWVudF9pZCI6InM2QmhkUmtxdDMiLCJyZWRpcmVjdF91cmkiOi" +
			       "JodHRwczpcL1wvY2xpZW50LmV4YW1wbGUuY29tXC9jYiIsInNjb3BlIjoib3BlbmlkIHByb2" +
			       "ZpbGUiLCJzdGF0ZSI6ImFmMGlmanNsZGtqIiwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJ1c2" +
			       "VyaW5mbyI6eyJjbGFpbXMiOnsibmFtZSI6bnVsbCwibmlja25hbWUiOnsib3B0aW9uYWwiOn" +
			       "RydWV9LCJlbWFpbCI6bnVsbCwidmVyaWZpZWQiOm51bGwsInBpY3R1cmUiOnsib3B0aW9uYW" +
			       "wiOnRydWV9fX0sImlkX3Rva2VuIjp7Im1heF9hZ2UiOjg2NDAwLCJjbGFpbXMiOnsiYWNyIj" +
			       "p7InZhbHVlcyI6WyIyIl19fX19.ou2Yc1B9a5iZLqbzBxE95aNS0pSfRClCqM77n85ehGo";
		
		AuthorizationRequest req = null;
		
		try {
			req = AuthorizationRequest.parse(query);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		ResponseTypeSet rts = req.getResponseTypeSet();
		assertNotNull(rts);
		assertTrue(rts.contains(ResponseType.CODE));
		assertTrue(rts.contains(ResponseType.ID_TOKEN));
		assertEquals(2, rts.size());
		
		assertEquals("s6BhdRkqt3", req.getClientID().getClaimValue());
		
		assertEquals("https://client.example.com/cb", req.getRedirectURI().toString());
		
		Scope scope = req.getScope();
		assertNotNull(scope);
		assertTrue(scope.contains(StdScopeToken.OPENID));
		assertEquals(1, scope.size());
		
		assertEquals(new Nonce("n-0S6_WzA2Mj"), req.getNonce());
		
		assertEquals(new State("af0ifjsldkj"), req.getState());
		
		// Request object
		assertTrue(req.hasRequestObject());
		assertNull(req.getRequestObjectURI());
		assertNotNull(req.getRequestObject());
		
		
		// Verify request object JWT
		
		try {
			boolean isValidSignature = ((SignedJWT)req.getRequestObject()).hmacVerify("aaa".getBytes("utf-8"));
			
			assertTrue(isValidSignature);
			
		} catch (java.io.UnsupportedEncodingException e) {
		
			fail(e.getMessage());
			
		} catch (com.nimbusds.jwt.JWSException e) {
			
			fail(e.getMessage());
		}
		
		// Get resolved request JSON object
		try {
			assertNotNull(req.getResolvedRequestObject());
			
		} catch (ResolveException e) {
		
			fail(e.getMessage());
		}
		
		
		// Resolve simple parameters
		try {
			// resolve response_type
			rts = req.getResolvedResponseTypeSet();
			assertNotNull(rts);
			assertTrue(rts.contains(ResponseType.CODE));
			assertTrue(rts.contains(ResponseType.ID_TOKEN));
			assertEquals(2, rts.size());
			
			// resolve client_id
			assertEquals("s6BhdRkqt3", req.getResolvedClientID().getClaimValue());
			
			// resolve redirect_uri
			assertEquals("https://client.example.com/cb", req.getResolvedRedirectURI().toString());
			
			// resolve scope
			scope = req.getResolvedScope();
			assertNotNull(scope);
			assertTrue(scope.contains(StdScopeToken.OPENID));
			assertTrue(scope.contains(StdScopeToken.PROFILE));
			assertEquals(2, scope.size());
			
			// resolve state
			assertEquals(new Nonce("n-0S6_WzA2Mj"), req.getResolvedNonce());
		
			// resolve nonce
			assertEquals(new State("af0ifjsldkj"), req.getResolvedState());
			
		} catch (ResolveException e) {
		
			fail(e.getMessage());
		}
		
		
		// Resolve claims
		ResolvedIDTokenClaimsRequest idTokenClaimsRequest = null;
		ResolvedUserInfoClaimsRequest userInfoClaimsRequest = null;
		
		try {
			idTokenClaimsRequest = req.getResolvedIDTokenClaimsRequest();
			userInfoClaimsRequest = req.getResolvedUserInfoClaimsRequest();
			
			assertEquals(86400, idTokenClaimsRequest.getMaxAge());
			
		} catch (ResolveException e) {
		
			fail(e.getMessage());
		}
		
		// ID Token claims
		
		Set<String> allClaims = idTokenClaimsRequest.getClaims();
		
		assertTrue(allClaims.contains("iss"));
		assertTrue(allClaims.contains("user_id"));
		assertTrue(allClaims.contains("aud"));
		assertTrue(allClaims.contains("exp"));
		assertTrue(allClaims.contains("iat"));
		assertTrue(allClaims.contains("nonce"));
		assertTrue(allClaims.contains("acr"));
		
		Set<String> requiredClaims = idTokenClaimsRequest.getRequiredClaims();
		
		assertTrue(requiredClaims.contains("iss"));
		assertTrue(requiredClaims.contains("user_id"));
		assertTrue(requiredClaims.contains("aud"));
		assertTrue(requiredClaims.contains("exp"));
		assertTrue(requiredClaims.contains("iat"));
		assertTrue(requiredClaims.contains("nonce"));
		
		try {
			assertNull(idTokenClaimsRequest.getUserID());
			assertEquals(86400, idTokenClaimsRequest.getMaxAge());
			String[] acr = idTokenClaimsRequest.getAuthenticationContextClassReference();
			
			assertEquals(1, acr.length);
			assertEquals("2", acr[0]);
			
		} catch (ResolveException e) {
		
			fail(e.getMessage());
		}
		
		Set<String> optionalClaims = idTokenClaimsRequest.getOptionalClaims();
		
		assertEquals(0, optionalClaims.size());
		
		
		// UserInfo claims
		
		allClaims = userInfoClaimsRequest.getClaims();
		
		assertTrue(allClaims.contains("user_id"));
		assertTrue(allClaims.contains("name"));
		assertTrue(allClaims.contains("family_name"));
		assertTrue(allClaims.contains("given_name"));
		assertTrue(allClaims.contains("middle_name"));
		assertTrue(allClaims.contains("nickname"));
		assertTrue(allClaims.contains("profile"));
		assertTrue(allClaims.contains("picture"));
		assertTrue(allClaims.contains("website"));
		assertTrue(allClaims.contains("gender"));
		assertTrue(allClaims.contains("birthday"));
		assertTrue(allClaims.contains("zoneinfo"));
		assertTrue(allClaims.contains("locale"));
		assertTrue(allClaims.contains("updated_time"));
		
		assertTrue(allClaims.contains("email"));
		assertTrue(allClaims.contains("verified"));
		
		assertEquals(16, allClaims.size());
		
		requiredClaims = userInfoClaimsRequest.getRequiredClaims();
		
		assertTrue(requiredClaims.contains("user_id"));
		assertTrue(requiredClaims.contains("name"));
		assertTrue(requiredClaims.contains("email"));
		assertTrue(requiredClaims.contains("verified"));
		
		assertEquals(4, requiredClaims.size());
		
		optionalClaims = userInfoClaimsRequest.getOptionalClaims();
		
		assertTrue(optionalClaims.contains("family_name"));
		assertTrue(optionalClaims.contains("given_name"));
		assertTrue(optionalClaims.contains("middle_name"));
		assertTrue(optionalClaims.contains("nickname"));
		assertTrue(optionalClaims.contains("profile"));
		assertTrue(optionalClaims.contains("picture"));
		assertTrue(optionalClaims.contains("website"));
		assertTrue(optionalClaims.contains("gender"));
		assertTrue(optionalClaims.contains("birthday"));
		assertTrue(optionalClaims.contains("zoneinfo"));
		assertTrue(optionalClaims.contains("locale"));
		assertTrue(optionalClaims.contains("updated_time"));
		
		assertEquals(12, optionalClaims.size());
	}
}
