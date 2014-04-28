package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.langtag.*;

import com.nimbusds.jwt.*;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.openid.connect.sdk.claims.*;


/**
 * Tests the OIDC authorisation request class.
 */
public class AuthenticationRequestTest extends TestCase {


	private final static String EXAMPLE_JWT_STRING = 
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
     		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
     		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	
	public void testMinimalConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		AuthenticationRequest request =
			new AuthenticationRequest(uri, rts, scope, clientID, redirectURI, state, nonce);

		assertEquals(uri, request.getEndpointURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));

		// Check the resulting query string
		String queryString = request.toQueryString();

		System.out.println("OIDC login query string: " + queryString);


		request = AuthenticationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getEndpointURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));
	}


	public void testAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		AuthenticationRequest request =
			new AuthenticationRequest(uri, rts, scope, clientID, redirectURI, state, nonce);

		// Check the resulting query string
		String queryString = request.toQueryString();

		request = AuthenticationRequest.parse(queryString);

		assertNull(request.getEndpointURI());

		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));
	}


	public void testExtendedConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<>();
		claimsLocales.add(LangTag.parse("en-US"));
		claimsLocales.add(LangTag.parse("en-GB"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		AuthenticationRequest request = new AuthenticationRequest(
			uri, rts, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, null, null);

		assertEquals(uri, request.getEndpointURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));

		// Check extended parameters

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		Prompt promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertTrue("UI locale en-US", uiLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("UI locale en-GB", uiLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertTrue("Claims locale en-US", claimsLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("Claims locale en-US", claimsLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		List<ACR> acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		ClaimsRequest claimsOut = request.getClaims();

		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());


		// Check the resulting query string
		String queryString = request.toQueryString();

		System.out.println("OIDC login query string: " + queryString);


		request = AuthenticationRequest.parse(uri, queryString);

		assertEquals(uri, request.getEndpointURI());
		
		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));

		// Check extended parameters

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertTrue("UI locale en-US", uiLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("UI locale en-GB", uiLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertTrue("Claims locale en-US", claimsLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("Claims locale en-US", claimsLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		claimsOut = request.getClaims();

		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());
	}


	public void testRequestObjectConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/login");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<>();
		claimsLocales.add(LangTag.parse("en-US"));
		claimsLocales.add(LangTag.parse("en-GB"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		JWT requestObject = JWTParser.parse(EXAMPLE_JWT_STRING);

		AuthenticationRequest request = new AuthenticationRequest(
			uri, rts, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, requestObject, null);

		assertEquals(uri, request.getEndpointURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));

		// Check extended parameters

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		Prompt promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertTrue("UI locale en-US", uiLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("UI locale en-GB", uiLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertTrue("Claims locale en-US", claimsLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("Claims locale en-US", claimsLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		List<ACR> acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		ClaimsRequest claimsOut = request.getClaims();

		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(EXAMPLE_JWT_STRING, request.getRequestObject().getParsedString());


		// Check the resulting query string
		String queryString = request.toQueryString();

		System.out.println("OIDC login query string: " + queryString);


		request = AuthenticationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getEndpointURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));

		// Check extended parameters

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertTrue("UI locale en-US", uiLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("UI locale en-GB", uiLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertTrue("Claims locale en-US", claimsLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("Claims locale en-US", claimsLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		claimsOut = request.getClaims();

		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(EXAMPLE_JWT_STRING, request.getRequestObject().getParsedString());
	}


	public void testRequestURIConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<>();
		claimsLocales.add(LangTag.parse("en-US"));
		claimsLocales.add(LangTag.parse("en-GB"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		URI requestURI = new URI("http://example.com/request-object.jwt#1234");

		AuthenticationRequest request = new AuthenticationRequest(
			uri, rts, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, null, requestURI);

		assertEquals(uri, request.getEndpointURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));

		// Check extended parameters

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		Prompt promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertTrue("UI locale en-US", uiLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("UI locale en-GB", uiLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertTrue("Claims locale en-US", claimsLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("Claims locale en-US", claimsLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		List<ACR> acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		ClaimsRequest claimsOut = request.getClaims();

		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(requestURI, request.getRequestURI());


		// Check the resulting query string
		String queryString = request.toQueryString();

		System.out.println("OIDC login query string: " + queryString);


		request = AuthenticationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getEndpointURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URI("http://www.deezer.com/en/").equals(request.getRedirectionURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));

		// Check extended parameters

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertTrue("UI locale en-US", uiLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("UI locale en-GB", uiLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertTrue("Claims locale en-US", claimsLocales.get(0).equals(LangTag.parse("en-US")));
		assertTrue("Claims locale en-US", claimsLocales.get(1).equals(LangTag.parse("en-GB")));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		claimsOut = request.getClaims();

		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(requestURI, request.getRequestURI());
	}


	public void testBuilderMinimal()
		throws Exception {

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code", "id_token"),
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb")).build();

		assertTrue(new ResponseType("code", "id_token").equals(request.getResponseType()));
		assertTrue(new Scope("openid", "email").equals(request.getScope()));
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertTrue(new URI("https://client.com/cb").equals(request.getRedirectionURI()));
		assertNull(request.getState());
		assertNull(request.getNonce());
		assertNull(request.getDisplay());
		assertNull(request.getPrompt());
		assertEquals(0, request.getMaxAge());
		assertNull(request.getUILocales());
		assertNull(request.getClaimsLocales());
		assertNull(request.getIDTokenHint());
		assertNull(request.getLoginHint());
		assertNull(request.getACRValues());
		assertNull(request.getClaims());
		assertNull(request.getRequestObject());
		assertNull(request.getRequestURI());
	}


	public void testBuilderFull()
		throws Exception {

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code", "id_token"),
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb")).
			state(new State("abc")).
			nonce(new Nonce("def")).
			display(Display.POPUP).
			prompt(new Prompt(Prompt.Type.NONE)).
			maxAge(3600).
			uiLocales(Arrays.asList(LangTag.parse("en-GB"), LangTag.parse("en-US"))).
			claimsLocales(Arrays.asList(LangTag.parse("bg-BG"), LangTag.parse("fr-FR"))).
			idTokenHint(JWTParser.parse(EXAMPLE_JWT_STRING)).
			loginHint("alice@wonderland.net").
			acrValues(acrValues).
			claims(claims).
			endpointURI(new URI("https://c2id.com/login")).
			build();

		assertTrue(new ResponseType("code", "id_token").equals(request.getResponseType()));
		assertTrue(new Scope("openid", "email").equals(request.getScope()));
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertTrue(new URI("https://client.com/cb").equals(request.getRedirectionURI()));
		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("def").equals(request.getNonce()));
		assertTrue(Display.POPUP.equals(request.getDisplay()));
		assertTrue(new Prompt(Prompt.Type.NONE).equals(request.getPrompt()));
		assertEquals(3600, request.getMaxAge());
		assertTrue(Arrays.asList(LangTag.parse("en-GB"), LangTag.parse("en-US")).equals(request.getUILocales()));
		assertTrue(Arrays.asList(LangTag.parse("bg-BG"), LangTag.parse("fr-FR")).equals(request.getClaimsLocales()));
		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());
		assertEquals("alice@wonderland.net", request.getLoginHint());
		assertEquals(acrValues, request.getACRValues());
		assertEquals(claims, request.getClaims());
		assertTrue(new URI("https://c2id.com/login").equals(request.getEndpointURI()));
	}


	public void testBuilderWithWithRequestObject()
		throws Exception {

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code", "id_token"),
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb")).
			requestObject(JWTParser.parse(EXAMPLE_JWT_STRING)).
			build();

		assertTrue(new ResponseType("code", "id_token").equals(request.getResponseType()));
		assertTrue(new Scope("openid", "email").equals(request.getScope()));
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertTrue(new URI("https://client.com/cb").equals(request.getRedirectionURI()));
		assertEquals(EXAMPLE_JWT_STRING, request.getRequestObject().getParsedString());
	}


	public void testBuilderWithRequestURI()
		throws Exception {

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code", "id_token"),
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb")).
			requestURI(new URI("https://client.com/request#123")).
			build();

		assertTrue(new ResponseType("code", "id_token").equals(request.getResponseType()));
		assertTrue(new Scope("openid", "email").equals(request.getScope()));
		assertTrue(new ClientID("123").equals(request.getClientID()));
		assertTrue(new URI("https://client.com/cb").equals(request.getRedirectionURI()));
		assertTrue(new URI("https://client.com/request#123").equals(request.getRequestURI()));
	}
}