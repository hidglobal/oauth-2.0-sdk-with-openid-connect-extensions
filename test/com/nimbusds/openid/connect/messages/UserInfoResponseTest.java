package com.nimbusds.openid.connect.messages;


import java.net.URL;

import javax.mail.internet.InternetAddress;

import junit.framework.TestCase;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.claims.UserInfo.Address;
import com.nimbusds.openid.connect.claims.UserInfo.Birthday;
import com.nimbusds.openid.connect.claims.UserInfo.Email;
import com.nimbusds.openid.connect.claims.UserInfo.FamilyName;
import com.nimbusds.openid.connect.claims.UserInfo.Gender;
import com.nimbusds.openid.connect.claims.UserInfo.GivenName;
import com.nimbusds.openid.connect.claims.UserInfo.Name;
import com.nimbusds.openid.connect.claims.UserInfo.Nickname;
import com.nimbusds.openid.connect.claims.UserInfo.Locale;
import com.nimbusds.openid.connect.claims.UserInfo.Picture;
import com.nimbusds.openid.connect.claims.UserInfo.PhoneNumber;
import com.nimbusds.openid.connect.claims.UserInfo.Profile;
import com.nimbusds.openid.connect.claims.UserInfo.UpdatedTime;
import com.nimbusds.openid.connect.claims.UserInfo.Verified;
import com.nimbusds.openid.connect.claims.UserInfo.Website;
import com.nimbusds.openid.connect.claims.UserInfo.Zoneinfo;
import com.nimbusds.openid.connect.claims.UserID;

import com.nimbusds.openid.connect.claims.sets.AddressClaims;
import com.nimbusds.openid.connect.claims.sets.UserInfoClaims;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * Tests UserInfo response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-23)
 */
public class UserInfoResponseTest extends TestCase {
	

	private static URL PROFILE_URL;
	
	
	private static URL PICTURE_URL;
	
	
	private static URL WEBSITE_URL;
	
	
	private static LangTag BG_LANGTAG;
	
	
	private static InternetAddress EMAIL;
	
	
	public void setUp()
		throws Exception {
	
		PROFILE_URL = new URL("http://wonderland.net/userinfo/alice");
		
		PICTURE_URL = new URL("http://wonderland.net/userinfo/alice.jpg");
		
		WEBSITE_URL = new URL("http://wonderland.net/blog/alice");
		
		EMAIL = new InternetAddress("alice@wonderland.net");
		
		BG_LANGTAG = new LangTag("bg");
		BG_LANGTAG.setRegion("BG");
	}
	
	
	public void testCreateSerializeAndParse() {
	
		UserID userID = new UserID();
		userID.setClaimValue("alice");
		
		UserInfoClaims claims = new UserInfoClaims(userID);
		
		Name name = new Name();
		name.setClaimValue("Alice");
		claims.addName(name);
		
		GivenName givenName = new GivenName();
		givenName.setClaimValue("Alice");
		claims.addGivenName(givenName);
		
		FamilyName familyName = new FamilyName();
		familyName.setClaimValue("Wonderland");
		claims.addFamilyName(familyName);
		
		Nickname nickname = new Nickname();
		nickname.setClaimValue("Alice");
		claims.addNickname(nickname);
		
		Profile profile = new Profile();
		profile.setClaimValue(PROFILE_URL);
		claims.setProfile(profile);
		
		Picture picture = new Picture();
		picture.setClaimValue(PICTURE_URL);
		claims.setPicture(picture);
		
		Website website = new Website();
		website.setClaimValue(WEBSITE_URL);
		claims.setWebsite(website);
		
		Email email = new Email();
		email.setClaimValue(EMAIL);
		claims.setEmail(email);
		
		Verified verified = new Verified();
		verified.setClaimValue(true);
		claims.setVerified(verified);
		
		Gender gender = new Gender();
		gender.setClaimValue(Gender.FEMALE);
		claims.setGender(gender);
		
		Birthday birthday = new Birthday();
		birthday.setClaimValue("31/12/2012");
		claims.setBirthday(birthday);
		
		Zoneinfo zoneinfo = new Zoneinfo();
		zoneinfo.setClaimValue("Europe/Sofia");
		claims.setZoneinfo(zoneinfo);
		
		Locale locale = new Locale();
		locale.setClaimValue("bg-BG");
		claims.setLocale(locale);
		
		PhoneNumber phoneNumber = new PhoneNumber();
		phoneNumber.setClaimValue("+359 (32) 100200");
		claims.setPhoneNumber(phoneNumber);
		
		UpdatedTime updatedTime = new UpdatedTime();
		updatedTime.setClaimValue("2011-01-03T23:58:42+0000");
		claims.setUpdatedTime(updatedTime);
		
		AddressClaims address = new AddressClaims();
		address.setLangTag(BG_LANGTAG);

		Address.Formatted formatted = new Address.Formatted();
		formatted.setClaimValue("Alice Wonderland\n36 Wonderland Str.\n1313 Wonder City\nWonderland");
		address.addFormatted(formatted);
		
		Address.StreetAddress streetAddress = new Address.StreetAddress();
		streetAddress.setClaimValue("36 Wonderland Str.");
		address.addStreetAddress(streetAddress);
		
		Address.Locality locality = new Address.Locality();
		locality.setClaimValue("Wonder City");
		address.addLocality(locality);
		
		Address.PostalCode postalCode = new Address.PostalCode();
		postalCode.setClaimValue("1313");
		address.addPostalCode(postalCode);
		
		Address.Country country = new Address.Country();
		country.setClaimValue("Wonderland");
		address.addCountry(country);
		
		claims.addAddress(address);
		
		System.out.println(claims.toJSONObject().toString());
		
		
		UserInfoResponse uir = new UserInfoResponse(claims);
		
		assertEquals(CommonContentTypes.APPLICATION_JSON, uir.getContentType());
		assertNotNull(uir.getUserInfoClaims());
		assertNull(uir.getUserInfoClaimsJWT());
		
		HTTPResponse httpResponse = null;
		
		try {
			httpResponse = uir.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(HTTPResponse.SC_OK, httpResponse.getStatusCode());
		assertEquals(CommonContentTypes.APPLICATION_JSON, httpResponse.getContentType());
		assertNotNull(httpResponse.getContent());
		
		
		try {
			uir = UserInfoResponse.parse(httpResponse);
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		
		assertEquals(CommonContentTypes.APPLICATION_JSON, uir.getContentType());
		assertNotNull(uir.getUserInfoClaims());
		assertNull(uir.getUserInfoClaimsJWT());
				
		claims = uir.getUserInfoClaims();

		assertEquals(userID, claims.getUserID());
		
		assertEquals(name, claims.getName());
		assertEquals(givenName, claims.getGivenName());
		assertEquals(familyName, claims.getFamilyName());
		assertEquals(nickname, claims.getNickname());
		
		assertEquals(profile, claims.getProfile());
		assertEquals(picture, claims.getPicture());
		assertEquals(website, claims.getWebsite());
		assertEquals(email, claims.getEmail());
		assertEquals(verified, claims.getVerified());
		
		assertEquals(gender, claims.getGender());
		assertEquals(birthday, claims.getBirthday());
		
		assertEquals(zoneinfo, claims.getZoneinfo());
		assertEquals(locale, claims.getLocale());
		assertEquals(phoneNumber, claims.getPhoneNumber());
		assertEquals(updatedTime, claims.getUpdatedTime());
		
		assertNull(claims.getAddress());
		
		assertEquals(formatted, claims.getAddress(BG_LANGTAG).getFormatted());
		assertEquals(streetAddress, claims.getAddress(BG_LANGTAG).getStreetAddress());
		assertEquals(locality, claims.getAddress(BG_LANGTAG).getLocality());
		assertEquals(postalCode, claims.getAddress(BG_LANGTAG).getPostalCode());
		assertEquals(country, claims.getAddress(BG_LANGTAG).getCountry());
	}
}
