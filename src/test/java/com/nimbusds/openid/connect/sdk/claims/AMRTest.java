package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;


/**
 * Tests the AMR class.
 */
public class AMRTest extends TestCase {
	

	public void testConstants() {

		assertEquals("eye", AMR.EYE.getValue());
		assertEquals("fpt", AMR.FPT.getValue());
		assertEquals("kba", AMR.KBA.getValue());
		assertEquals("mca", AMR.MCA.getValue());
		assertEquals("mfa", AMR.MFA.getValue());
		assertEquals("otp", AMR.OTP.getValue());
		assertEquals("pop", AMR.POP.getValue());
		assertEquals("pwd", AMR.PWD.getValue());
		assertEquals("rba", AMR.RBA.getValue());
		assertEquals("sc", AMR.SC.getValue());
		assertEquals("sms", AMR.SMS.getValue());
		assertEquals("tel", AMR.TEL.getValue());
		assertEquals("user", AMR.USER.getValue());
		assertEquals("wia", AMR.WIA.getValue());
	}
}
