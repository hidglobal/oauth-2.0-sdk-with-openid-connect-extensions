package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTException;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPRequest;


/**
 * Tests check ID request serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-22)
 */
public class CheckIDRequestTest extends TestCase {
	
	
	public void testParseAndSerialize() {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		final String idTokenString = 
			"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC" +
			"9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiaH" +
			"R0cDpcL1wvY2xpZW50LmV4YW1wbGUuY29tIiwiZXhwIjoxMzExMjgxOTcwfQ.eDesUD0vzDH" +
			"3T1G3liaTNOrfaeWYjuRCEPNXVtaazNQ";
		
		final String postBody = "access_token=" + idTokenString;
		
		httpRequest.setQuery(postBody);
		
		
		CheckIDRequest cir = null;
		
		try {
			cir = CheckIDRequest.parse(httpRequest);
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		AccessToken accessToken = null;
		
		try {
			accessToken = cir.getAccessToken();
			
		} catch (JWTException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(accessToken);
		assertEquals(idTokenString, accessToken.getValue());
		
		
		JWT jwt = null;
		
		try {
			jwt = cir.getJWT();
			
		} catch (JWTException e) {
		
			fail(e.getMessage());
		}		
		
		assertNotNull(jwt);
		System.out.println(jwt.getClaimsSet().toJSONObject());
		
		assertTrue(jwt instanceof SignedJWT);
		
		SignedJWT signedJWT = (SignedJWT)jwt;
		System.out.println(signedJWT.getHeader().getAlgorithm().toString());
		
		
		try {
			httpRequest = cir.toHTTPRequest();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals(postBody, httpRequest.getQuery());
	}
}
