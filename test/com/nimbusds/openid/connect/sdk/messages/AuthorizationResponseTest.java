package com.nimbusds.openid.connect.sdk.messages;


import java.net.MalformedURLException;
import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.HTTPResponse;


/**
 * Tests authorisation response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-22)
 */
public class AuthorizationResponseTest extends TestCase {
	
	
	private static URL ABS_REDIRECT_URL = null;
	
	
	private static URL REL_REDIRECT_URL = null;
	
	
	private static String ID_TOKEN_STRING = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9zZ" +
	                                        "XJ2ZXIuZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiaHR0c" +
	                                        "DpcL1wvY2xpZW50LmV4YW1wbGUuY29tIiwiZXhwIjoxMzExMjgxOTcwfQ.eDesUD0vzDH3T1" +
	                                        "G3liaTNOrfaeWYjuRCEPNXVtaazNQ";
	
	
	private static JWT ID_TOKEN = null;
	
	
	public void setUp()
		throws MalformedURLException, java.text.ParseException {
		
		ABS_REDIRECT_URL = new URL("https://client.example.com/cb");
		
		REL_REDIRECT_URL = new URL("https://");
		
		ID_TOKEN = JWTParser.parse(ID_TOKEN_STRING);
	}
	
	
	public void testConstructorMinimal() {
	
		AuthorizationResponse resp = new AuthorizationResponse(ABS_REDIRECT_URL, null, null, null, null);
		
		assertEquals(ABS_REDIRECT_URL.toString(), resp.getRedirectURI().toString());
		
		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(0, rts.size());
		
		assertNull(resp.getAuthorizationCode());
		assertNull(resp.getAccessToken());
		assertNull(resp.getIDToken());
		
		assertNull(resp.getState());
		
		try {
			resp.toURL();
			
			fail("Failed to raise exception");
			
		} catch (IllegalStateException e) {
		
			// ok
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
	}
	
	
	public void testSerializeCode() {
		
		AuthorizationCode code = new AuthorizationCode("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk");
		
		State state = new State("af0ifjsldkj");
		
		AuthorizationResponse resp = new AuthorizationResponse(ABS_REDIRECT_URL, code, null, null, state);
		
		
		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(1, rts.size());
		assertTrue(rts.contains(ResponseType.CODE));
		
		assertEquals(code.getValue(), resp.getAuthorizationCode().getValue());
		assertEquals(state.toString(), resp.getState().toString());
		
		URL url = null;
		HTTPResponse httpResp = null;
		
		try {
			url = resp.toURL();
			httpResp = resp.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals("https://client.example.com/cb?code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk&state=af0ifjsldkj",
		             url.toString());
				     
		assertEquals(HTTPResponse.SC_FOUND, httpResp.getStatusCode());
		
		assertEquals("https://client.example.com/cb?code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk&state=af0ifjsldkj",
		             httpResp.getLocation().toString());
	}
	
	
	public void testParseCode() {
	
		AuthorizationResponse resp = null;
		
		try {
			resp = AuthorizationResponse.parse(new URL("https://client.example.com/cb?code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk&state=af0ifjsldkj"));
			
		} catch (MalformedURLException e) {
		
			fail(e.getMessage());
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(1, rts.size());
		assertTrue(rts.contains(ResponseType.CODE));
		
		AuthorizationCode code = resp.getAuthorizationCode();
		assertEquals("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk", code.getValue());
		
		State state = resp.getState();
		assertEquals("af0ifjsldkj", state.toString());
	}
	
	
	public void testSerializeTokenAndIDToken() {
		
		AccessToken token = new AccessToken("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");
				
		State state = new State("af0ifjsldkj");
		
		AuthorizationResponse resp = new AuthorizationResponse(ABS_REDIRECT_URL, null, ID_TOKEN, token, state);
		
		
		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(2, rts.size());
		assertTrue(rts.contains(ResponseType.TOKEN));
		assertTrue(rts.contains(ResponseType.ID_TOKEN));
		
		assertEquals("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y", resp.getAccessToken().getValue());
		assertNotNull(resp.getIDToken());
		assertEquals(state.toString(), resp.getState().toString());
		
		URL url = null;
		HTTPResponse httpResp = null;
		
		try {
			url = resp.toURL();
			httpResp = resp.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(url);
		assertTrue(url.toString().startsWith("https://client.example.com/cb#"));
		assertTrue(url.toString().indexOf("access_token=jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y") > 0);
		assertTrue(url.toString().indexOf("token_type=Bearer") > 0);
		assertTrue(url.toString().indexOf("id_token=") > 0);
		assertTrue(url.toString().indexOf("state=af0ifjsldkj") > 0);
				     
		assertEquals(HTTPResponse.SC_FOUND, httpResp.getStatusCode());
	}
	
	
	public void testParseTokenAndIDToken() {
	
	
	
	}
}
