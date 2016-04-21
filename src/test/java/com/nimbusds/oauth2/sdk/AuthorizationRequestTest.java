package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import junit.framework.TestCase;


public class AuthorizationRequestTest extends TestCase {


	public void testRegisteredParameters() {

		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("response_type"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("response_mode"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("client_id"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("redirect_uri"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("scope"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("state"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("code_challenge"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("code_challenge_method"));
		assertEquals(8, AuthorizationRequest.getRegisteredParameterNames().size());
	}
	
	
	public void testMinimal()
		throws Exception {
		
		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,String> params = URLUtils.parseParameters(query);
		assertEquals("code", params.get("response_type"));
		assertEquals("123456", params.get("client_id"));
		assertEquals(2, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(uri, httpReq.getURL().toURI());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(uri, query);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getResponseMode());
		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testMinimalAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

		String query = req.toQueryString();

		req = AuthorizationRequest.parse(query);

		assertNull(req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertNull(req.getResponseMode());
		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testToRequestURIWithParse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ResponseType rts = new ResponseType("code");
		ClientID clientID = new ClientID("123456");
		URI endpointURI = new URI("https://c2id.com/login");

		AuthorizationRequest req = new AuthorizationRequest.Builder(rts, clientID).
			redirectionURI(redirectURI).
			endpointURI(endpointURI).
			build();

		URI requestURI = req.toURI();

		assertTrue(requestURI.toString().startsWith(endpointURI.toString() + "?"));
		req = AuthorizationRequest.parse(requestURI);

		assertEquals(endpointURI, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testFull()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ResponseMode rm = ResponseMode.FORM_POST;

		ClientID clientID = new ClientID("123456");

		URI redirectURI = new URI("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);

		Map<String,String> customParams = new HashMap<>();
		customParams.put("x", "100");
		customParams.put("y", "200");
		customParams.put("z", "300");


		AuthorizationRequest req = new AuthorizationRequest(uri, rts, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, customParams);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(rm, req.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,String> params = URLUtils.parseParameters(query);

		assertEquals("code", params.get("response_type"));
		assertEquals("form_post", params.get("response_mode"));
		assertEquals("123456", params.get("client_id"));
		assertEquals(redirectURI.toString(), params.get("redirect_uri"));
		assertEquals(scope, Scope.parse(params.get("scope")));
		assertEquals(state, new State(params.get("state")));
		assertEquals(codeChallenge.getValue(), params.get("code_challenge"));
		assertEquals(codeChallengeMethod.getValue(), params.get("code_challenge_method"));
		assertEquals("100", params.get("x"));
		assertEquals("200", params.get("y"));
		assertEquals("300", params.get("z"));
		assertEquals(11, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(uri, query);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(rm, req.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(codeChallenge, req.getCodeChallenge());
		assertEquals(codeChallengeMethod, req.getCodeChallengeMethod());
		assertEquals("100", req.getCustomParameter("x"));
		assertEquals("200", req.getCustomParameter("y"));
		assertEquals("300", req.getCustomParameter("z"));
		assertEquals("100", req.getCustomParameters().get("x"));
		assertEquals("200", req.getCustomParameters().get("y"));
		assertEquals("300", req.getCustomParameters().get("z"));
		assertEquals(3, req.getCustomParameters().size());
	}


	public void testFullAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		URI redirectURI = new URI("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		CodeVerifier verifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, verifier);

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, null, clientID, redirectURI, scope, state, codeChallenge, null);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());

		String query = req.toQueryString();

		req = AuthorizationRequest.parse(query);

		assertNull(req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(codeChallenge, req.getCodeChallenge());
		assertNull(req.getCodeChallengeMethod());
	}


	public void testBuilderMinimal()
		throws Exception {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123")).build();

		assertTrue(new ResponseType("code").equals(request.getResponseType()));
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalAlt()
		throws Exception {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123")).build();

		assertTrue(new ResponseType("token").equals(request.getResponseType()));
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalNullCodeChallenge()
		throws Exception {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123"))
			.codeChallenge(null, null)
			.build();

		assertTrue(new ResponseType("token").equals(request.getResponseType()));
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderFull()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123")).
			endpointURI(new URI("https://c2id.com/login")).
			redirectionURI(new URI("https://client.com/cb")).
			scope(new Scope("openid", "email")).
			state(new State("123")).
			responseMode(ResponseMode.FORM_POST).
			codeChallenge(codeChallenge, CodeChallengeMethod.S256).
			build();

		assertTrue(new ResponseType("code").equals(request.getResponseType()));
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertTrue(new Scope("openid", "email").equals(request.getScope()));
		assertTrue(new State("123").equals(request.getState()));
		assertEquals(codeChallenge, request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.S256, request.getCodeChallengeMethod());
	}


	public void testBuilderFullAlt()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, codeVerifier);


		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.endpointURI(new URI("https://c2id.com/login"))
			.redirectionURI(new URI("https://client.com/cb"))
			.scope(new Scope("openid", "email"))
			.state(new State("123"))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(codeChallenge, null)
			.customParameter("x", "100")
			.customParameter("y", "200")
			.customParameter("z", "300")
			.build();

		assertTrue(new ResponseType("code").equals(request.getResponseType()));
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertTrue(new Scope("openid", "email").equals(request.getScope()));
		assertTrue(new State("123").equals(request.getState()));
		assertEquals(codeChallenge, request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertEquals("100", request.getCustomParameter("x"));
		assertEquals("200", request.getCustomParameter("y"));
		assertEquals("300", request.getCustomParameter("z"));
		assertEquals("100", request.getCustomParameters().get("x"));
		assertEquals("200", request.getCustomParameters().get("y"));
		assertEquals("300", request.getCustomParameters().get("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testParseExceptionMissingClientID()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=code" +
			"&state=xyz" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing \"client_id\" parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing \"client_id\" parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseExceptionInvalidRedirectionURI()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=code" +
			"&client_id=s6BhdRkqt3" +
			"&state=xyz" +
			"&redirect_uri=%3A");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertTrue(e.getMessage().startsWith("Invalid \"redirect_uri\" parameter"));
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertTrue(e.getErrorObject().getDescription().startsWith("Invalid request: Invalid \"redirect_uri\" parameter"));
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseExceptionMissingResponseType()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=" +
			"&client_id=123" +
			"&state=xyz" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing \"response_type\" parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing \"response_type\" parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
	public void testParseWithEncodedEqualsChar()
		throws Exception {

		URI redirectURI = URI.create("https://client.com/in?app=123");

		String encodedRedirectURI = URLEncoder.encode(redirectURI.toString(), "UTF-8");

		URI requestURI = URI.create("https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=" +
			encodedRedirectURI);

		AuthorizationRequest request = AuthorizationRequest.parse(requestURI);

		assertEquals(ResponseType.parse("code"), request.getResponseType());
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new State("xyz"), request.getState());
		assertEquals(redirectURI, request.getRedirectionURI());
	}
}
