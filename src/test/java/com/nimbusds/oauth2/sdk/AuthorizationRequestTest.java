package com.nimbusds.oauth2.sdk;


import java.net.URL;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Tests authorisation request serialisation and parsing.
 */
public class AuthorizationRequestTest extends TestCase {
	
	
	public void testMinimal()
		throws Exception {
		
		URL uri = new URL("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

		assertEquals(uri, req.getURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,String> params = URLUtils.parseParameters(query);
		assertEquals("code", params.get("response_type"));
		assertEquals("123456", params.get("client_id"));
		assertEquals(2, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(uri, httpReq.getURL());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(uri, query);

		assertEquals(uri, req.getURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
	}


	public void testMinimalAltParse()
		throws Exception {

		URL uri = new URL("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

		String query = req.toQueryString();

		req = AuthorizationRequest.parse(query);

		assertNull(req.getURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
	}


	public void testFull()
		throws Exception {

		URL uri = new URL("https://c2id.com/authz/");
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		URL redirectURI = new URL("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID, redirectURI, scope, state);

		assertEquals(uri, req.getURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,String> params = URLUtils.parseParameters(query);

		assertEquals("code", params.get("response_type"));
		assertEquals("123456", params.get("client_id"));
		assertEquals(redirectURI.toString(), params.get("redirect_uri"));
		assertEquals(scope, Scope.parse(params.get("scope")));
		assertEquals(state, new State(params.get("state")));
		assertEquals(5, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(uri, query);

		assertEquals(uri, req.getURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
	}


	public void testFullAltParse()
		throws Exception {

		URL uri = new URL("https://c2id.com/authz/");
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		URL redirectURI = new URL("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID, redirectURI, scope, state);

		assertEquals(uri, req.getURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());

		String query = req.toQueryString();

		req = AuthorizationRequest.parse(query);

		assertNull(req.getURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
	}
}
