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


	public void testWithAddress()
		throws Exception {

		String json = "{\n" +
			"\"sub\": \"248289761001\",\n" +
			"\"name\": \"Jane Doe\",\n" +
			"\"email\": \"janedoe@example.com\",\n" +
			"\"address\": {\n" +
			"\"formatted\":\"Some formatted\",\n" +
			"\"street_address\":\"Some street\",\n" +
			"\"locality\":\"Some locality\",\n" +
			"\"region\":\"Some region\",\n" +
			"\"postal_code\":\"1000\",\n" +
			"\"country\":\"Some country\"\n" +
			"}   \n" +
			"}";

		UserInfo userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("janedoe@example.com", userInfo.getEmail().getAddress());

		Address address = userInfo.getAddress();

		assertEquals("Some formatted", address.getFormatted());
		assertEquals("Some street", address.getStreetAddress());
		assertEquals("Some locality", address.getLocality());
		assertEquals("Some region", address.getRegion());
		assertEquals("1000", address.getPostalCode());
		assertEquals("Some country", address.getCountry());

		json = userInfo.toJSONObject().toJSONString();

		userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("janedoe@example.com", userInfo.getEmail().getAddress());

		address = userInfo.getAddress();

		assertEquals("Some formatted", address.getFormatted());
		assertEquals("Some street", address.getStreetAddress());
		assertEquals("Some locality", address.getLocality());
		assertEquals("Some region", address.getRegion());
		assertEquals("1000", address.getPostalCode());
		assertEquals("Some country", address.getCountry());
	}
}
