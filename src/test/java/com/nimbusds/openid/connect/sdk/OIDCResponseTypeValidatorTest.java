package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ResponseType;
import junit.framework.TestCase;


/**
 * Tests the OIDC response type validator.
 * 
 * @author Vladimir Dzhuvinov
 */
public class OIDCResponseTypeValidatorTest extends TestCase {


	public void testPass() {
		
		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		
		OIDCResponseTypeValidator.validate(rt);
	}
	
	
	public void testEmptyResponseType() {
		
		ResponseType rt = new ResponseType();
		
		try {
			OIDCResponseTypeValidator.validate(rt);
			
			fail("Failed to raise exception");
		} catch (IllegalArgumentException e) {
			// ok
		}
	}
	
	
	public void testTokenOnlyResponseType() {
		
		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.TOKEN);
		
		try {
			OIDCResponseTypeValidator.validate(rt);
			
			fail("Failed to raise exception");
		} catch (IllegalArgumentException e) {
			// ok
		}
	}
	
	
	public void testUnsupportedResponseType() {
		
		ResponseType rt = new ResponseType();
		rt.add(new ResponseType.Value("abc"));
		
		try {
			OIDCResponseTypeValidator.validate(rt);
			
			fail("Failed to raise exception");
		} catch (IllegalArgumentException e) {
			// ok
		}
	}
	
	
	public void testCodeTokenIDTokenResponseType() {
		
		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		rt.add(ResponseType.Value.TOKEN);
		rt.add(OIDCResponseTypeValue.ID_TOKEN);
		
		OIDCResponseTypeValidator.validate(rt);
	}
}