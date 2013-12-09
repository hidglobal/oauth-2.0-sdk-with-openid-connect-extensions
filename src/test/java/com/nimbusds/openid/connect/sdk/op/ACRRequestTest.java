package com.nimbusds.openid.connect.sdk.op;


import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCAuthorizationRequest;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;


/**
 * Tests the ACR request class.
 */
public class ACRRequestTest extends TestCase {
	
	
	public void testConstructAndGet() {
		
		List<ACR> essentialACRs = new ArrayList<ACR>();
		essentialACRs.add(new ACR("1"));
		
		List<ACR> voluntaryACRs = new ArrayList<ACR>();
		voluntaryACRs.add(new ACR("2"));
		
		ACRRequest req = new ACRRequest(essentialACRs, voluntaryACRs);
		
		assertEquals(essentialACRs, req.getEssentialACRs());
		assertEquals(voluntaryACRs, req.getVoluntaryACRs());
		
		assertEquals(1, req.getEssentialACRs().size());
		assertEquals(1, req.getVoluntaryACRs().size());
	}
	
	
	public void testConstructAndGetNull() {
		
		ACRRequest req = new ACRRequest(null, null);
		
		assertNull(req.getEssentialACRs());
		assertNull(req.getVoluntaryACRs());
	}
	
	
	public void testResolveNone()
		throws Exception {
		
		URL requestURI = new URL("https://c2id.com/authz");
		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		Scope scope = Scope.parse("openid profile");
		ClientID clientID = new ClientID("abc");
		URL redirectURI = new URL("https://example.com/in");
		State state = new State();
		Nonce nonce = new Nonce();
		
		
		OIDCAuthorizationRequest authzRequest = new OIDCAuthorizationRequest(requestURI, 
			rt, scope, clientID, redirectURI, state, nonce);
		
		ACRRequest acrRequest = ACRRequest.resolve(authzRequest);
		
		assertNull(acrRequest.getEssentialACRs());
		assertNull(acrRequest.getVoluntaryACRs());
		
		assertTrue(acrRequest.isEmpty());
	}
	
	
	public void testResolveTopLevelACRRequest()
		throws Exception {
		
		URL requestURI = new URL("https://c2id.com/authz");
		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		Scope scope = Scope.parse("openid profile");
		ClientID clientID = new ClientID("abc");
		URL redirectURI = new URL("https://example.com/in");
		State state = new State();
		Nonce nonce = new Nonce();
		Display display = Display.POPUP;
		Prompt prompt = Prompt.parse("login");
		int maxAge = 3600;
		List<ACR> acrValues = new ArrayList<ACR>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));
		ClaimsRequest claims = null;
		
		OIDCAuthorizationRequest authzRequest = new OIDCAuthorizationRequest(requestURI, 
			rt, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, null, null, null, null, acrValues, claims);
		
		ACRRequest acrRequest = ACRRequest.resolve(authzRequest);
		
		assertNull(acrRequest.getEssentialACRs());
		
		List<ACR> voluntaryACRs = acrRequest.getVoluntaryACRs();
		
		assertTrue(voluntaryACRs.contains(new ACR("1")));
		assertTrue(voluntaryACRs.contains(new ACR("2")));
		
		assertEquals(2, voluntaryACRs.size());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testResolveClaimsLevelEssentialACRRequest()
		throws Exception {
		
		URL requestURI = new URL("https://c2id.com/authz");
		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		Scope scope = Scope.parse("openid profile");
		ClientID clientID = new ClientID("abc");
		URL redirectURI = new URL("https://example.com/in");
		State state = new State();
		Nonce nonce = new Nonce();
		Display display = Display.POPUP;
		Prompt prompt = Prompt.parse("login");
		int maxAge = 3600;
		List<ACR> acrValues = null;
		
		ClaimsRequest claims = new ClaimsRequest();
		
		List<String> essentialACRs = new ArrayList<String>();
		essentialACRs.add("A");
		essentialACRs.add("B");
		claims.addIDTokenClaim("acr", ClaimRequirement.ESSENTIAL, null, essentialACRs);
		
		OIDCAuthorizationRequest authzRequest = new OIDCAuthorizationRequest(requestURI, 
			rt, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, null, null, null, null, acrValues, claims);
		
		ACRRequest acrRequest = ACRRequest.resolve(authzRequest);
		
		assertTrue(acrRequest.getEssentialACRs().contains(new ACR("A")));
		assertTrue(acrRequest.getEssentialACRs().contains(new ACR("B")));
		assertEquals(2, acrRequest.getEssentialACRs().size());
		
		assertNull(acrRequest.getVoluntaryACRs());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testResolveClaimsLevelVoluntaryACRRequest()
		throws Exception {
		
		URL requestURI = new URL("https://c2id.com/authz");
		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		Scope scope = Scope.parse("openid profile");
		ClientID clientID = new ClientID("abc");
		URL redirectURI = new URL("https://example.com/in");
		State state = new State();
		Nonce nonce = new Nonce();
		Display display = Display.POPUP;
		Prompt prompt = Prompt.parse("login");
		int maxAge = 3600;
		List<ACR> acrValues = null;
		
		ClaimsRequest claims = new ClaimsRequest();
		
		List<String> essentialACRs = new ArrayList<String>();
		essentialACRs.add("A");
		essentialACRs.add("B");
		claims.addIDTokenClaim("acr", ClaimRequirement.VOLUNTARY, null, essentialACRs);
		
		OIDCAuthorizationRequest authzRequest = new OIDCAuthorizationRequest(requestURI, 
			rt, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, null, null, null, null, acrValues, claims);
		
		ACRRequest acrRequest = ACRRequest.resolve(authzRequest);
		
		assertNull(acrRequest.getEssentialACRs());
		
		assertTrue(acrRequest.getVoluntaryACRs().contains(new ACR("A")));
		assertTrue(acrRequest.getVoluntaryACRs().contains(new ACR("B")));
		assertEquals(2, acrRequest.getVoluntaryACRs().size());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testResolveMixedACRRequest()
		throws Exception {
		
		URL requestURI = new URL("https://c2id.com/authz");
		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		Scope scope = Scope.parse("openid profile");
		ClientID clientID = new ClientID("abc");
		URL redirectURI = new URL("https://example.com/in");
		State state = new State();
		Nonce nonce = new Nonce();
		Display display = Display.POPUP;
		Prompt prompt = Prompt.parse("login");
		int maxAge = 3600;
		List<ACR> acrValues = new ArrayList<ACR>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));
		
		ClaimsRequest claims = new ClaimsRequest();
		
		List<String> essentialACRs = new ArrayList<String>();
		essentialACRs.add("A");
		essentialACRs.add("B");
		claims.addIDTokenClaim("acr", ClaimRequirement.ESSENTIAL, null, essentialACRs);
		
		OIDCAuthorizationRequest authzRequest = new OIDCAuthorizationRequest(requestURI, 
			rt, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, null, null, null, null, acrValues, claims);
		
		ACRRequest acrRequest = ACRRequest.resolve(authzRequest);
		
		assertTrue(acrRequest.getEssentialACRs().contains(new ACR("A")));
		assertTrue(acrRequest.getEssentialACRs().contains(new ACR("B")));
		assertEquals(2, acrRequest.getEssentialACRs().size());
		
		assertTrue(acrRequest.getVoluntaryACRs().contains(new ACR("1")));
		assertTrue(acrRequest.getVoluntaryACRs().contains(new ACR("2")));
		assertEquals(2, acrRequest.getVoluntaryACRs().size());
		
		assertFalse(acrRequest.isEmpty());
	}
}