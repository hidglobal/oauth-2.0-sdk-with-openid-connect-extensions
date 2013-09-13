package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;


/**
 * Tests the UserInfo claims set.
 *
 * @author Vladimir Dzhuvinov
 */
public class UserInfoTest extends TestCase {


	public void testParseRoundTrip()
		throws Exception {

		// Example JSON from messages spec
		String json = "{\n" +
			"   \"sub\"                : \"248289761001\",\n" +
			"   \"name\"               : \"Jane Doe\",\n" +
			"   \"given_name\"         : \"Jane\",\n" +
			"   \"family_name\"        : \"Doe\",\n" +
			"   \"preferred_username\" : \"j.doe\",\n" +
			"   \"email\"              : \"janedoe@example.com\",\n" +
			"   \"picture\"            : \"http://example.com/janedoe/me.jpg\"\n" +
			" }";

		UserInfo userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("Jane", userInfo.getGivenName());
		assertEquals("Doe", userInfo.getFamilyName());
		assertEquals("j.doe", userInfo.getPreferredUsername());
		assertEquals("janedoe@example.com", userInfo.getEmail().getAddress());
		assertEquals("http://example.com/janedoe/me.jpg", userInfo.getPicture().toString());

		json = userInfo.toJSONObject().toJSONString();

		userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("Jane", userInfo.getGivenName());
		assertEquals("Doe", userInfo.getFamilyName());
		assertEquals("j.doe", userInfo.getPreferredUsername());
		assertEquals("janedoe@example.com", userInfo.getEmail().getAddress());
		assertEquals("http://example.com/janedoe/me.jpg", userInfo.getPicture().toString());
	}
}
