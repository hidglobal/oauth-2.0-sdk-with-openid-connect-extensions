package com.nimbusds.openid.connect.sdk.claims;


import java.net.URL;

import javax.mail.internet.InternetAddress;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.DateUtils;
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


	public void testConstructor() {

		Subject subject = new Subject("alice");

		UserInfo userInfo = new UserInfo(subject);

		assertEquals(subject.getValue(), userInfo.getSubject().getValue());
		assertNull(userInfo.getName());
		assertNull(userInfo.getGivenName());
		assertNull(userInfo.getFamilyName());
		assertNull(userInfo.getMiddleName());
		assertNull(userInfo.getNickname());
		assertNull(userInfo.getPreferredUsername());
		assertNull(userInfo.getProfile());
		assertNull(userInfo.getPicture());
		assertNull(userInfo.getWebsite());
		assertNull(userInfo.getEmail());
		assertNull(userInfo.getEmailVerified());
		assertNull(userInfo.getGender());
		assertNull(userInfo.getBirthdate());
		assertNull(userInfo.getZoneinfo());
		assertNull(userInfo.getLocale());
		assertNull(userInfo.getPhoneNumber());
		assertNull(userInfo.getPhoneNumberVerified());
		assertNull(userInfo.getAddress());
		assertNull(userInfo.getUpdatedTime());
	}


	public void testGettersAndSetters()
		throws Exception {

		UserInfo userInfo = new UserInfo(new Subject("sub"));

		userInfo.setName("name");
		userInfo.setGivenName("given_name");
		userInfo.setFamilyName("family_name");
		userInfo.setMiddleName("middle_name");
		userInfo.setNickname("nickname");
		userInfo.setPreferredUsername("preferred_username");
		userInfo.setProfile(new URL("https://profile.com"));
		userInfo.setPicture(new URL("https://picture.com"));
		userInfo.setWebsite(new URL("https://website.com"));
		userInfo.setEmail(new InternetAddress("name@domain.com"));
		userInfo.setEmailVerified(true);
		userInfo.setGender(Gender.FEMALE);
		userInfo.setBirthdate("1992-01-31");
		userInfo.setZoneinfo("Europe/Paris");
		userInfo.setLocale("en-GB");
		userInfo.setPhoneNumber("phone_number");
		userInfo.setPhoneNumberVerified(true);

		Address address = new Address();
		address.setFormatted("formatted");
		address.setStreetAddress("street_address");
		address.setLocality("locality");
		address.setRegion("region");
		address.setPostalCode("postal_code");
		address.setCountry("country");

		userInfo.setAddress(address);

		userInfo.setUpdatedTime(DateUtils.fromSecondsSinceEpoch(100000l));

		assertEquals("sub", userInfo.getSubject().getValue());
		assertEquals("given_name", userInfo.getGivenName());
		assertEquals("family_name", userInfo.getFamilyName());
		assertEquals("middle_name", userInfo.getMiddleName());
		assertEquals("nickname", userInfo.getNickname());
		assertEquals("preferred_username", userInfo.getPreferredUsername());
		assertEquals("https://profile.com", userInfo.getProfile().toString());
		assertEquals("https://picture.com", userInfo.getPicture().toString());
		assertEquals("https://website.com", userInfo.getWebsite().toString());
		assertEquals("name@domain.com", userInfo.getEmail().getAddress());
		assertTrue(userInfo.getEmailVerified());
		assertEquals(Gender.FEMALE, userInfo.getGender());
		assertEquals("1992-01-31", userInfo.getBirthdate());
		assertEquals("Europe/Paris", userInfo.getZoneinfo());
		assertEquals("en-GB", userInfo.getLocale());
		assertEquals("phone_number", userInfo.getPhoneNumber());
		assertTrue(userInfo.getPhoneNumberVerified());

		address = userInfo.getAddress();
		assertEquals("formatted", address.getFormatted());
		assertEquals("street_address", address.getStreetAddress());
		assertEquals("locality", address.getLocality());
		assertEquals("region", address.getRegion());
		assertEquals("postal_code", address.getPostalCode());
		assertEquals("country", address.getCountry());

		String json = userInfo.toJSONObject().toString();

		System.out.println("Full UserInfo: " + json);

		userInfo = UserInfo.parse(json);

		assertEquals("sub", userInfo.getSubject().getValue());
		assertEquals("given_name", userInfo.getGivenName());
		assertEquals("family_name", userInfo.getFamilyName());
		assertEquals("middle_name", userInfo.getMiddleName());
		assertEquals("nickname", userInfo.getNickname());
		assertEquals("preferred_username", userInfo.getPreferredUsername());
		assertEquals("https://profile.com", userInfo.getProfile().toString());
		assertEquals("https://picture.com", userInfo.getPicture().toString());
		assertEquals("https://website.com", userInfo.getWebsite().toString());
		assertEquals("name@domain.com", userInfo.getEmail().getAddress());
		assertTrue(userInfo.getEmailVerified());
		assertEquals(Gender.FEMALE, userInfo.getGender());
		assertEquals("1992-01-31", userInfo.getBirthdate());
		assertEquals("Europe/Paris", userInfo.getZoneinfo());
		assertEquals("en-GB", userInfo.getLocale());
		assertEquals("phone_number", userInfo.getPhoneNumber());
		assertTrue(userInfo.getPhoneNumberVerified());

		address = userInfo.getAddress();
		assertEquals("formatted", address.getFormatted());
		assertEquals("street_address", address.getStreetAddress());
		assertEquals("locality", address.getLocality());
		assertEquals("region", address.getRegion());
		assertEquals("postal_code", address.getPostalCode());
		assertEquals("country", address.getCountry());
	}


	public void testLanguageTaggedGettersAndSetters()
		throws Exception {

		UserInfo userInfo = new UserInfo(new Subject("sub"));

		userInfo.setName("name#en", LangTag.parse("en"));
		userInfo.setName("name#bg", LangTag.parse("bg"));

		userInfo.setGivenName("given_name#en", LangTag.parse("en"));
		userInfo.setGivenName("given_name#bg", LangTag.parse("bg"));

		userInfo.setFamilyName("family_name#en", LangTag.parse("en"));
		userInfo.setFamilyName("family_name#bg", LangTag.parse("bg"));

		userInfo.setMiddleName("middle_name#en", LangTag.parse("en"));
		userInfo.setMiddleName("middle_name#bg", LangTag.parse("bg"));

		userInfo.setNickname("nickname#en", LangTag.parse("en"));
		userInfo.setNickname("nickname#bg", LangTag.parse("bg"));

		Address address = new Address();
		address.setFormatted("formatted#en");

		userInfo.setAddress(address, LangTag.parse("en"));

		address = new Address();
		address.setFormatted("formatted#bg");

		userInfo.setAddress(address, LangTag.parse("bg"));

		assertEquals("name#en", userInfo.getName(LangTag.parse("en")));
		assertEquals("name#bg", userInfo.getName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getNameEntries().size());

		assertEquals("given_name#en", userInfo.getGivenName(LangTag.parse("en")));
		assertEquals("given_name#bg", userInfo.getGivenName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getGivenNameEntries().size());

		assertEquals("family_name#en", userInfo.getFamilyName(LangTag.parse("en")));
		assertEquals("family_name#bg", userInfo.getFamilyName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getFamilyNameEntries().size());

		assertEquals("middle_name#en", userInfo.getMiddleName(LangTag.parse("en")));
		assertEquals("middle_name#bg", userInfo.getMiddleName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getMiddleNameEntries().size());

		assertEquals("nickname#en", userInfo.getNickname(LangTag.parse("en")));
		assertEquals("nickname#bg", userInfo.getNickname(LangTag.parse("bg")));
		assertEquals(2, userInfo.getNicknameEntries().size());

		assertEquals("formatted#en", userInfo.getAddress(LangTag.parse("en")).getFormatted());
		assertEquals("formatted#bg", userInfo.getAddress(LangTag.parse("bg")).getFormatted());
		assertEquals(2, userInfo.getAddressEntries().size());

		String json = userInfo.toJSONObject().toJSONString();

		userInfo = UserInfo.parse(json);

		assertEquals("name#en", userInfo.getName(LangTag.parse("en")));
		assertEquals("name#bg", userInfo.getName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getNameEntries().size());

		assertEquals("given_name#en", userInfo.getGivenName(LangTag.parse("en")));
		assertEquals("given_name#bg", userInfo.getGivenName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getGivenNameEntries().size());

		assertEquals("family_name#en", userInfo.getFamilyName(LangTag.parse("en")));
		assertEquals("family_name#bg", userInfo.getFamilyName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getFamilyNameEntries().size());

		assertEquals("middle_name#en", userInfo.getMiddleName(LangTag.parse("en")));
		assertEquals("middle_name#bg", userInfo.getMiddleName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getMiddleNameEntries().size());

		assertEquals("nickname#en", userInfo.getNickname(LangTag.parse("en")));
		assertEquals("nickname#bg", userInfo.getNickname(LangTag.parse("bg")));
		assertEquals(2, userInfo.getNicknameEntries().size());

		assertEquals("formatted#en", userInfo.getAddress(LangTag.parse("en")).getFormatted());
		assertEquals("formatted#bg", userInfo.getAddress(LangTag.parse("bg")).getFormatted());
		assertEquals(2, userInfo.getAddressEntries().size());
	}
}
