package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Tests authorisation request serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-10)
 */
public class AuthorizationRequestTest extends TestCase {
	
	
	public void testMinimal()
		throws Exception {

		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(rts, clientID);

		assertEquals(rts, req.getResponseTypeSet());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getRedirectURI());
		assertNull(req.getScope());
		assertNull(req.getState());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,String> params = URLUtils.parseParameters(query);
		assertEquals("code", params.get("response_type"));
		assertEquals("123456", params.get("client_id"));
		assertEquals(2, params.size());

		HTTPRequest httpReq = req.toHTTPRequest(new URL("https://connect2id.com/authz/"));
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(query);

		assertEquals(rts, req.getResponseTypeSet());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getRedirectURI());
		assertNull(req.getScope());
		assertNull(req.getState());
	}


	public void testFull()
		throws Exception {

		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);

		ClientID clientID = new ClientID("123456");

		URL redirectURI = new URL("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		AuthorizationRequest req = new AuthorizationRequest(rts, clientID, redirectURI, scope, state);

		assertEquals(rts, req.getResponseTypeSet());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectURI());
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

		HTTPRequest httpReq = req.toHTTPRequest(new URL("https://connect2id.com/authz/"));
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(query);

		assertEquals(rts, req.getResponseTypeSet());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
	}
}
