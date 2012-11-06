package com.nimbusds.openid.connect.sdk.messages;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.claims.ClientID;


/**
 * Tests authorisation request serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-06)
 */
public class AuthorizationRequestTest extends TestCase {
	
	
	public void testSerializeSimple() {
	
		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);
		rts.add(ResponseType.ID_TOKEN);
		
		Scope scope = new Scope();
		scope.add(ScopeToken.OPENID);
		
		ClientID clientID = new ClientID();
		clientID.setClaimValue("s6BhdRkqt3");
		
		URL redirectURI = null;
		
		try {
			redirectURI = new URL("https://client.example.com/cb");
		
		} catch (MalformedURLException e) {
		
			fail(e.getMessage());
		}
		
		Nonce nonce = new Nonce("n-0S6_WzA2Mj");
		
		State state = new State("af0ifjsldkj");
		
		AuthorizationRequest authReq = new AuthorizationRequest(
			rts, scope, clientID, redirectURI, nonce, state, null, null, null);
		
		
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
		assertTrue(authReq.getScope().contains(ScopeToken.OPENID));
		
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
		assertTrue(scope.contains(ScopeToken.OPENID));
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
			       "&request=eyJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSBpZF" +
			       "90b2tlbiIsImNsaWVudF9pZCI6InM2QmhkUmtxdDMiLCJyZWRpcmVjdF91cmkiOi" +
			       "JodHRwczpcL1wvY2xpZW50LmV4YW1wbGUuY29tXC9jYiIsInNjb3BlIjoib3Blbm" + 
			       "lkIHByb2ZpbGUiLCJzdGF0ZSI6ImFmMGlmanNsZGtqIiwibm9uY2UiOiJuLTBTNl" +
			       "9XekEyTWoiLCJ1c2VyaW5mbyI6eyJjbGFpbXMiOnsibmFtZSI6eyJlc3NlbnRpYW" +
			       "wiOnRydWV9LCJuaWNrbmFtZSI6bnVsbCwiZW1haWwiOnsiZXNzZW50aWFsIjp0cn" +
			       "VlfSwiZW1haWxfdmVyaWZpZWQiOnsiZXNzZW50aWFsIjp0cnVlfSwicGljdHVyZS" +
			       "I6bnVsbH19LCJpZF90b2tlbiI6eyJtYXhfYWdlIjo4NjQwMCwiY2xhaW1zIjp7Im" +
			       "FjciI6eyJ2YWx1ZXMiOlsiMiJdfX19fQ.krAJHvc-vo5ntIc5suj2u3gU75nZ1IC" +
			       "cidLEw8OCNyOlTR4Gk6etZDr5lozMFzhDSXAJ5TxhfUJLsp8VSum8spnmbGaqKr4" +
			       "bEWTirUDGE3TsJCHRQZLzwuAYlLcS-ZaHVk9ue0oB7q_GeGTAIDHBncJP1x1j-MP" +
			       "vNxWbYXQ4wo9O6Y8QnbyOrrLl5LHRMrvlLFnc0uqt5QKHqcQa6l9wYQjjWJXoZir" +
			       "sWdJ_wmSsfbQCWMRtA6JNbV0q0gImbOGno75GxFKNkguW5JBU4Vj5gEafz2EPSxV" +
			       "sRNWf6MtFvXqOLSZMqoKK40b2akbj0kGdZ8aPPSMoywaGclKlIHh0PQ";
		
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
		assertTrue(scope.contains(ScopeToken.OPENID));
		assertEquals(1, scope.size());
		
		assertEquals(new Nonce("n-0S6_WzA2Mj"), req.getNonce());
		
		assertEquals(new State("af0ifjsldkj"), req.getState());
		
		// Request object
		assertTrue(req.hasRequestObject());
		assertNull(req.getRequestObjectURI());
		assertNotNull(req.getRequestObject());
		assertTrue(req.getRequestObject() instanceof JWSObject);
	}
}
