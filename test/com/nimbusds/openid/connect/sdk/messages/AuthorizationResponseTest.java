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
 * <p>The test vectors are from the OIDC spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-17)
 */
public class AuthorizationResponseTest extends TestCase {
	
	
	private static URL ABS_REDIRECT_URL = null;
	
	
	private static URL REL_REDIRECT_URL = null;
	
	
	private static String ID_TOKEN_STRING = 
		"eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL3Nlc" +
		"nZlci5leGFtcGxlLmNvbSIsDQogICAgInVzZXJfaWQiOiAiMjQ4Mjg5NzYxMDAxI" +
		"iwNCiAgICAiYXVkIjogInM2QmhkUmtxdDMiLA0KICAgICJub25jZSI6ICJuLTBTN" +
		"l9XekEyTWoiLA0KICAgICJleHAiOiAxMzExMjgxOTcwLA0KICAgICJpYXQiOiAxM" +
		"zExMjgwOTcwLA0KICAgICJhdF9oYXNoIjogIjc3UW1VUHRqUGZ6V3RGMkFucEs5U" +
		"ldwWHJXbHJlY2RiTFV5SkRJYjdTNlEiDQp9.ZP0kFjn7ZOYwga5dbfvvYLlu7DAa" +
		"RRhgE7u88OEfRqmfWCB35mwSso1A255fbvdOPryGda3xy0t2P1gjNxc2cKA8T9Rm" +
		"w0ae6UyLSaA9zROXfpdyRX6wEs_RMdnftBY60B_DCeFJkWQxUG6taXomiVH7Ozyk" +
		"765VX3gRzSoxaJKbD1xo582s0dGmMvkUL4dg7-46eOrOLkQTujUAOnjqCfiqzL1C" +
		"rchYsNZjwNBE8pySRhJTmedm882k0NRZPU1QMLJIVpB9e0Hiuwz1htHm3-XxZ63b" +
		"bzRLG6jsWknphWIFraFrf59Kgmct7jfzBF5IOvfpcdFe9kHVkKX_acts-w";
	
	
	private static JWT ID_TOKEN = null;


	private static String CODE_STRING = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";


	private static AuthorizationCode CODE = new AuthorizationCode(CODE_STRING);


	private static String TOKEN_STRING = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";


	private static AccessToken TOKEN = new AccessToken(TOKEN_STRING);


	private static String STATE_STRING = "af0ifjsldkj";


	private static State STATE = new State(STATE_STRING);


	private static String RESPONSE_CODE = 
		"https://client.example.org/cb?code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk&state=af0ifjsldkj";


	private static String RESPOSE_TOKEN_ID_TOKEN = 
		"https://client.example.org/cb#" + 
		"access_token=jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y" +
		"&token_type=Bearer" +
		"&id_token=eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL3Nlc" +
		"nZlci5leGFtcGxlLmNvbSIsDQogICAgInVzZXJfaWQiOiAiMjQ4Mjg5NzYxMDAxI" +
		"iwNCiAgICAiYXVkIjogInM2QmhkUmtxdDMiLA0KICAgICJub25jZSI6ICJuLTBTN" +
		"l9XekEyTWoiLA0KICAgICJleHAiOiAxMzExMjgxOTcwLA0KICAgICJpYXQiOiAxM" +
		"zExMjgwOTcwLA0KICAgICJhdF9oYXNoIjogIjc3UW1VUHRqUGZ6V3RGMkFucEs5U" +
		"ldwWHJXbHJlY2RiTFV5SkRJYjdTNlEiDQp9.ZP0kFjn7ZOYwga5dbfvvYLlu7DAa" +
		"RRhgE7u88OEfRqmfWCB35mwSso1A255fbvdOPryGda3xy0t2P1gjNxc2cKA8T9Rm" +
		"w0ae6UyLSaA9zROXfpdyRX6wEs_RMdnftBY60B_DCeFJkWQxUG6taXomiVH7Ozyk" +
		"765VX3gRzSoxaJKbD1xo582s0dGmMvkUL4dg7-46eOrOLkQTujUAOnjqCfiqzL1C" +
		"rchYsNZjwNBE8pySRhJTmedm882k0NRZPU1QMLJIVpB9e0Hiuwz1htHm3-XxZ63b" +
		"bzRLG6jsWknphWIFraFrf59Kgmct7jfzBF5IOvfpcdFe9kHVkKX_acts-w";


	private static String RESPONSE_TOKEN_CODE = 
		"https://client.example.org/cb#" +
		"code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk" +
		"&access_token=jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y" +
		"&token_type=Bearer" +
		"&state=af0ifjsldkj";
	
	
	public void setUp()
		throws MalformedURLException, 
		       java.text.ParseException {
		
		ABS_REDIRECT_URL = new URL("https://client.example.org/cb");
		
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
		
		AuthorizationResponse resp = new AuthorizationResponse(ABS_REDIRECT_URL, CODE, null, null, STATE);
		
		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(1, rts.size());
		assertTrue(rts.contains(ResponseType.CODE));
		
		assertEquals(CODE_STRING, resp.getAuthorizationCode().getValue());
		assertEquals(STATE_STRING, resp.getState().toString());
		
		URL url = null;
		HTTPResponse httpResp = null;
		
		try {
			url = resp.toURL();
			httpResp = resp.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(RESPONSE_CODE, url.toString());
				     
		assertEquals(HTTPResponse.SC_FOUND, httpResp.getStatusCode());
		
		assertEquals(RESPONSE_CODE, httpResp.getLocation().toString());
	}
	
	
	public void testParseCode() {
	
		AuthorizationResponse resp = null;
		
		try {
			resp = AuthorizationResponse.parse(new URL(RESPONSE_CODE));
			
		} catch (MalformedURLException e) {
		
			fail(e.getMessage());
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(1, rts.size());
		assertTrue(rts.contains(ResponseType.CODE));
		
		AuthorizationCode code = resp.getAuthorizationCode();
		assertEquals(CODE_STRING, code.getValue());
		
		State state = resp.getState();
		assertEquals(STATE_STRING, state.toString());
	}
	
	
	public void testSerializeTokenAndIDToken() {
		
		AuthorizationResponse resp = new AuthorizationResponse(ABS_REDIRECT_URL, null, ID_TOKEN, TOKEN, STATE);
		
		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(2, rts.size());
		assertTrue(rts.contains(ResponseType.TOKEN));
		assertTrue(rts.contains(ResponseType.ID_TOKEN));
		
		assertEquals(TOKEN_STRING, resp.getAccessToken().getValue());
		assertEquals(ID_TOKEN_STRING, resp.getIDToken().getParsedString());
		assertEquals(STATE_STRING, resp.getState().toString());
		
		URL url = null;
		HTTPResponse httpResp = null;
		
		try {
			url = resp.toURL();
			httpResp = resp.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(url);
		assertTrue(url.toString().startsWith(ABS_REDIRECT_URL.toString() + "#"));
		assertTrue(url.toString().indexOf("access_token=" + TOKEN) > 0);
		assertTrue(url.toString().indexOf("token_type=Bearer") > 0);
		assertTrue(url.toString().indexOf("id_token=") > 0);
		assertTrue(url.toString().indexOf("state=" + STATE_STRING) > 0);
				     
		assertEquals(HTTPResponse.SC_FOUND, httpResp.getStatusCode());
	}
	
	
	public void testParseTokenAndIDToken() {
	
		AuthorizationResponse resp = null;

		try {
			resp = AuthorizationResponse.parse(new URL(RESPOSE_TOKEN_ID_TOKEN));
			
		} catch (MalformedURLException e) {
		
			fail(e.getMessage());
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}


		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(2, rts.size());
		assertTrue(rts.contains(ResponseType.TOKEN));
		assertTrue(rts.contains(ResponseType.ID_TOKEN));


		JWT idToken = resp.getIDToken();
		assertEquals(ID_TOKEN_STRING, idToken.getParsedString());

		AccessToken token = resp.getAccessToken();
		assertEquals(TOKEN_STRING, token.getValue());
	}


	public void testSerializeTokenAndCode() {
		
		AuthorizationResponse resp = new AuthorizationResponse(ABS_REDIRECT_URL, CODE, null, TOKEN, STATE);
		
		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(2, rts.size());
		assertTrue(rts.contains(ResponseType.CODE));
		assertTrue(rts.contains(ResponseType.TOKEN));
		
		assertEquals(CODE_STRING, resp.getAuthorizationCode().getValue());
		assertEquals(TOKEN_STRING, resp.getAccessToken().getValue());
		assertEquals(STATE_STRING, resp.getState().toString());
		
		URL url = null;
		HTTPResponse httpResp = null;
		
		try {
			url = resp.toURL();
			httpResp = resp.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(url);
		assertTrue(url.toString().startsWith(ABS_REDIRECT_URL.toString() + "#"));
		assertTrue(url.toString().indexOf("code=" + CODE_STRING) > 0);
		assertTrue(url.toString().indexOf("access_token=" + TOKEN) > 0);
		assertTrue(url.toString().indexOf("token_type=Bearer") > 0);
		
		assertTrue(url.toString().indexOf("state=" + STATE_STRING) > 0);
				     
		assertEquals(HTTPResponse.SC_FOUND, httpResp.getStatusCode());
	}


	public void testParseTokenAndCode() {
	
		AuthorizationResponse resp = null;

		try {
			resp = AuthorizationResponse.parse(new URL(RESPONSE_TOKEN_CODE));
			
		} catch (MalformedURLException e) {
		
			fail(e.getMessage());
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}


		ResponseTypeSet rts = resp.getResponseTypeSet();
		assertEquals(2, rts.size());
		assertTrue(rts.contains(ResponseType.CODE));
		assertTrue(rts.contains(ResponseType.TOKEN));


		AuthorizationCode code = resp.getAuthorizationCode();
		assertEquals(CODE_STRING, code.getValue());

		AccessToken token = resp.getAccessToken();
		assertEquals(TOKEN_STRING, token.getValue());

		State state = resp.getState();
		assertEquals(STATE, state);
	}
}
