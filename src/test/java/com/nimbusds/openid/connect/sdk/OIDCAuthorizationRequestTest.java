package com.nimbusds.openid.connect.sdk;


import java.net.URL;
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
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCAuthorizationRequestTest extends TestCase {


	private final static String EXAMPLE_JWT_STRING = 
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
     		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
     		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	
	public void testMinimalConstructor()
		throws Exception {

		URL uri = new URL("https://c2id.com/authz/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URL redirectURI = new URL("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		OIDCAuthorizationRequest request = 
			new OIDCAuthorizationRequest(uri, rts, scope, clientID, redirectURI, state, nonce);

		assertEquals(uri, request.getURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URL("http://www.deezer.com/en/").equals(request.getRedirectURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));

		// Check the resulting query string
		String queryString = request.toQueryString();

		System.out.println("OIDC authz query string: " + queryString);


		request = OIDCAuthorizationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URL("http://www.deezer.com/en/").equals(request.getRedirectURI()));

		assertTrue(new State("abc").equals(request.getState()));
		assertTrue(new Nonce("xyz").equals(request.getNonce()));
	}


	public void testExtendedConstructor()
		throws Exception {

		URL uri = new URL("https://c2id.com/authz/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URL redirectURI = new URL("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<LangTag>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<LangTag>();
		claimsLocales.add(LangTag.parse("en-US"));
		claimsLocales.add(LangTag.parse("en-GB"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<ACR>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		OIDCAuthorizationRequest request = 
			new OIDCAuthorizationRequest(uri, rts, scope, clientID, redirectURI, state, nonce, 
				                     display, prompt, maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues, claims);

		assertEquals(uri, request.getURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URL("http://www.deezer.com/en/").equals(request.getRedirectURI()));

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

		System.out.println("OIDC authz request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());


		// Check the resulting query string
		String queryString = request.toQueryString();

		System.out.println("OIDC authz query string: " + queryString);


		request = OIDCAuthorizationRequest.parse(uri, queryString);

		assertEquals(uri, request.getURI());
		
		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URL("http://www.deezer.com/en/").equals(request.getRedirectURI()));

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

		System.out.println("OIDC authz request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());
	}


	public void testRequestObjectConstructor()
		throws Exception {

		URL uri = new URL("https://c2id.com/authz");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URL redirectURI = new URL("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<LangTag>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<LangTag>();
		claimsLocales.add(LangTag.parse("en-US"));
		claimsLocales.add(LangTag.parse("en-GB"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<ACR>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		JWT requestObject = JWTParser.parse(EXAMPLE_JWT_STRING);

		OIDCAuthorizationRequest request = 
			new OIDCAuthorizationRequest(uri, rts, scope, clientID, redirectURI, state, nonce, 
				                     display, prompt, maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues, claims,
				                     requestObject);

		assertEquals(uri, request.getURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URL("http://www.deezer.com/en/").equals(request.getRedirectURI()));

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

		System.out.println("OIDC authz request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(EXAMPLE_JWT_STRING, request.getRequestObject().getParsedString());


		// Check the resulting query string
		String queryString = request.toQueryString();

		System.out.println("OIDC authz query string: " + queryString);


		request = OIDCAuthorizationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URL("http://www.deezer.com/en/").equals(request.getRedirectURI()));

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

		System.out.println("OIDC authz request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(EXAMPLE_JWT_STRING, request.getRequestObject().getParsedString());
	}


	public void testRequestURIConstructor()
		throws Exception {

		URL uri = new URL("https://c2id.com/authz/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URL redirectURI = new URL("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<LangTag>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<LangTag>();
		claimsLocales.add(LangTag.parse("en-US"));
		claimsLocales.add(LangTag.parse("en-GB"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<ACR>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		URL requestURI = new URL("http://example.com/request-object.jwt#1234");

		OIDCAuthorizationRequest request = 
			new OIDCAuthorizationRequest(uri, rts, scope, clientID, redirectURI, state, nonce, 
				                     display, prompt, maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues, claims,
				                     requestURI);

		assertEquals(uri, request.getURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URL("http://www.deezer.com/en/").equals(request.getRedirectURI()));

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

		System.out.println("OIDC authz request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(requestURI, request.getRequestURI());


		// Check the resulting query string
		String queryString = request.toQueryString();

		System.out.println("OIDC authz query string: " + queryString);


		request = OIDCAuthorizationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());

		assertTrue(new ClientID("123456789").equals(request.getClientID()));

		assertTrue(new URL("http://www.deezer.com/en/").equals(request.getRedirectURI()));

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

		System.out.println("OIDC authz request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(requestURI, request.getRequestURI());
	}
}