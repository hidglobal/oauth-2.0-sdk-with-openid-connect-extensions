package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * Tests claim name parsing into name base and optional language tag.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-23)
 */
public class ClaimNameTest extends TestCase {


	public void testParseNull() {
	
		assertNull(ClaimName.parse(null));
	}
	
	
	public void testParseBaseOnly() {
	
		ClaimName cn = ClaimName.parse("family_name");

		assertNotNull(cn);
		
		assertEquals("family_name", cn.getBase());
		assertNull(cn.getLangTag());
	}
	
	
	public void testParseComposite() {
	
		ClaimName cn = ClaimName.parse("family_name#en-GB");
		
		assertNotNull(cn);
		
		assertEquals("family_name", cn.getBase());
		assertEquals("en-GB", cn.getLangTag().toString());
	}
	
	
	public void testParseCompositeWithBadLangTag() {
	
		ClaimName cn = ClaimName.parse("family_name#en_GB");
		
		assertNotNull(cn);
		
		assertEquals("family_name#en_GB", cn.getBase());
		assertNull(cn.getLangTag());
	}
}
	
	
