package com.nimbusds.openid.connect.sdk.claims;


import java.net.URL;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.oauth2.sdk.id.Subject;


/**
 * UserInfo claims set, serialisable to a JSON object.
 *
 * <p>Example UserInfo claims set:
 *
 * <pre>
 * {
 *   "sub"                : "248289761001",
 *   "name"               : "Jane Doe",
 *   "given_name"         : "Jane",
 *   "family_name"        : "Doe",
 *   "preferred_username" : "j.doe",
 *   "email"              : "janedoe@example.com",
 *   "picture"            : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.5.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class UserInfo extends ClaimsSet {


	/**
	 * The names of the standard top-level UserInfo claims.
	 */
	private static final Set<String> stdClaimNames = new LinkedHashSet<String>();
	
	
	static {
		stdClaimNames.add("sub");
		stdClaimNames.add("name");
		stdClaimNames.add("given_name");
		stdClaimNames.add("family_name");
		stdClaimNames.add("middle_name");
		stdClaimNames.add("nickname");
		stdClaimNames.add("preferred_username");
		stdClaimNames.add("profile");
		stdClaimNames.add("picture");
		stdClaimNames.add("website");
		stdClaimNames.add("email");
		stdClaimNames.add("email_verified");
		stdClaimNames.add("gender");
		stdClaimNames.add("birthdate");
		stdClaimNames.add("zoneinfo");
		stdClaimNames.add("locale");
		stdClaimNames.add("phone_number");
		stdClaimNames.add("phone_number_verified");
		stdClaimNames.add("address");
		stdClaimNames.add("updated_at");
	}
	
	
	/**
	 * Gets the names of the standard top-level UserInfo claims.
	 *
	 * @return The names of the standard top-level UserInfo claims 
	 *         (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
	
		return Collections.unmodifiableSet(stdClaimNames);
	}
	
	
	/**
	 * Creates a new minimal UserInfo claims set.
	 *
	 * @param sub The subject. Must not be {@code null}.
	 */
	public UserInfo(final Subject sub) {
	
		setClaim("sub", sub.getValue());
	}


	/**
	 * Creates a new UserInfo claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the JSON object doesn't contain
	 *                                  a subject {@code sub} string claim.
	 */
	public UserInfo(final JSONObject jsonObject) {

		super(jsonObject);

		if (getSubject() == null)
			throw new IllegalArgumentException("Missing or invalid \"sub\" claim");
	}
	
	
	/**
	 * Gets the UserInfo subject. Corresponds to the {@code sub} claim.
	 *
	 * @return The subject, {@code null} if not specified.
	 */
	public Subject getSubject() {
	
		String value = getStringClaim("sub");

		if (value != null)
			return new Subject(value);
		else
			return null;
	}

	
	/**
	 * Gets the full name. Corresponds to the {@code name} claim, with no
	 * language tag.
	 *
	 * @return The full name, {@code null} if not specified.
	 */
	public String getName() {
	
		return getStringClaim("name");
	}
	
	
	/**
	 * Gets the full name. Corresponds to the {@code name} claim, with an
	 * optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The full name, {@code null} if not specified.
	 */
	public String getName(final LangTag langTag) {
	
		return getStringClaim("name", langTag);
	}
	
	
	/**
	 * Gets the full name entries. Correspond to the {@code name} claim.
	 *
	 * @return The full name entries, empty map if none.
	 */
	public Map<LangTag,String> getNameEntries() {
	
		return getLangTaggedClaim("name", String.class);
	}


	/**
	 * Sets the full name. Corresponds to the {@code name} claim, with no
	 * language tag.
	 *
	 * @param name The full name. If {@code null} the claim will be 
	 *             removed.
	 */
	public void setName(final String name) {
	
		setClaim("name", name);
	}
	
	
	/**
	 * Sets the full name. Corresponds to the {@code name} claim, with an
	 * optional language tag.
	 *
	 * @param name    The full name. If {@code null} the claim will be 
	 *                removed.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setName(final String name, final LangTag langTag) {
	
		setClaim("name", name, langTag);
	}	
	
	
	/**
	 * Gets the given or first name. Corresponds to the {@code given_name} 
	 * claim, with no language tag.
	 *
	 * @return The given or first name, {@code null} if not specified.
	 */
	public String getGivenName() {
	
		return getStringClaim("given_name");
	}
	
	
	/**
	 * Gets the given or first name. Corresponds to the {@code given_name} 
	 * claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The given or first name, {@code null} if not specified.
	 */
	public String getGivenName(final LangTag langTag) {
	
		return getStringClaim("given_name", langTag);
	}
	
	
	/**
	 * Gets the given or first name entries. Correspond to the 
	 * {@code given_name} claim.
	 *
	 * @return The given or first name entries, empty map if none.
	 */
	public Map<LangTag,String> getGivenNameEntries() {
	
		return getLangTaggedClaim("given_name", String.class);
	}


	/**
	 * Sets the given or first name. Corresponds to the {@code given_name} 
	 * claim, with no language tag.
	 *
	 * @param givenName The given or first name. If {@code null} the claim
	 *                  will be removed.
	 */
	public void setGivenName(final String givenName) {
	
		setClaim("given_name", givenName);
	}
	
	
	/**
	 * Sets the given or first name. Corresponds to the {@code given_name}
	 * claim, with an optional language tag.
	 *
	 * @param givenName The given or first full name. If {@code null} the 
	 *                  claim will be removed.
	 * @param langTag   The language tag, {@code null} if not specified.
	 */
	public void setGivenName(final String givenName, final LangTag langTag) {
	
		setClaim("given_name", givenName, langTag);
	}

	
	/**
	 * Gets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with no language tag.
	 *
	 * @return The surname or last name, {@code null} if not specified.
	 */
	public String getFamilyName() {
	
		return getStringClaim("family_name");
	}
	
	
	/**
	 * Gets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The surname or last name, {@code null} if not specified.
	 */
	public String getFamilyName(final LangTag langTag) {
	
		return getStringClaim("family_name", langTag);
	}
	
	
	/**
	 * Gets the surname or last name entries. Correspond to the 
	 * @code family_name} claim.
	 *
	 * @return The surname or last name entries, empty map if none.
	 */
	public Map<LangTag,String> getFamilyNameEntries() {
	
		return getLangTaggedClaim("family_name", String.class);
	}


	/**
	 * Sets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with no language tag.
	 *
	 * @param familyName The surname or last name. If {@code null} the 
	 *                   claim will be removed.
	 */
	public void setFamilyName(final String familyName) {
	
		setClaim("family_name", familyName);
	}
	
	
	/**
	 * Sets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with an optional language tag.
	 *
	 * @param familyName The surname or last name. If {@code null} the 
	 *                   claim will be removed.
	 * @param langTag    The language tag, {@code null} if not specified.
	 */
	public void setFamilyName(final String familyName, final LangTag langTag) {
	
		setClaim("family_name", familyName, langTag);
	}

	
	/**
	 * Gets the middle name. Corresponds to the {@code middle_name} claim, 
	 * with no language tag.
	 *
	 * @return The middle name, {@code null} if not specified.
	 */
	public String getMiddleName() {
	
		return getStringClaim("middle_name");
	}
	
	
	/**
	 * Gets the middle name. Corresponds to the {@code middle_name} claim,
	 * with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The middle name, {@code null} if not specified.
	 */
	public String getMiddleName(final LangTag langTag) {
	
		return getStringClaim("middle_name", langTag);
	}
	
	
	/**
	 * Gets the middle name entries. Correspond to the {@code middle_name}
	 * claim.
	 *
	 * @return The middle name entries, empty map if none.
	 */
	public Map<LangTag,String> getMiddleNameEntries() {
	
		return getLangTaggedClaim("middle_name", String.class);
	}


	/**
	 * Sets the middle name. Corresponds to the {@code middle_name} claim,
	 * with no language tag.
	 *
	 * @param middleName The middle name. If {@code null} the claim will be
	 *                   removed.
	 */
	public void setMiddleName(final String middleName) {
	
		setClaim("middle_name", middleName);
	}
	
	
	/**
	 * Sets the middle name. Corresponds to the {@code middle_name} claim, 
	 * with an optional language tag.
	 *
	 * @param middleName The middle name. If {@code null} the claim will be
	 *                   removed.
	 * @param langTag    The language tag, {@code null} if not specified.
	 */
	public void setMiddleName(final String middleName, final LangTag langTag) {
	
		setClaim("middle_name", middleName, langTag);
	}
	
	
	/**
	 * Gets the casual name. Corresponds to the {@code nickname} claim, 
	 * with no language tag.
	 *
	 * @return The casual name, {@code null} if not specified.
	 */
	public String getNickname() {
	
		return getStringClaim("nickname");
	}
	
	
	/**
	 * Gets the casual name. Corresponds to the {@code nickname} claim, 
	 * with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The casual name, {@code null} if not specified.
	 */
	public String getNickname(final LangTag langTag) {
	
		return getStringClaim("nickname", langTag);
	}
	
	
	/**
	 * Gets the casual name entries. Correspond to the {@code nickname} 
	 * claim.
	 *
	 * @return The casual name entries, empty map if none.
	 */
	public Map<LangTag,String> getNicknameEntries() {
	
		return getLangTaggedClaim("nickname", String.class);
	}


	/**
	 * Sets the casual name. Corresponds to the {@code nickname} claim, 
	 * with no language tag.
	 *
	 * @param nickname The casual name. If {@code null} the claim will be
	 *                 removed.
	 */
	public void setNickname(final String nickname) {
	
		setClaim("nickname", nickname);
	}
	
	
	/**
	 * Sets the casual name. Corresponds to the {@code nickname} claim, 
	 * with an optional language tag.
	 *
	 * @param nickname The casual name. If {@code null} the claim will be
	 *                 removed.
	 * @param langTag  The language tag, {@code null} if not specified.
	 */
	public void setNickname(final String nickname, final LangTag langTag) {
	
		setClaim("nickname", nickname, langTag);
	}
	
	
	/**
	 * Gets the preferred username. Corresponds to the 
	 * {@code preferred_username} claim.
	 *
	 * @return The preferred username, {@code null} if not specified.
	 */
	public String getPreferredUsername() {
	
		return getStringClaim("preferred_username");
	}
	
	
	/**
	 * Sets the preferred username. Corresponds to the 
	 * {@code preferred_username} claim.
	 *
	 * @param preferredUsername The preferred username. If {@code null} the
	 *                          claim will be removed.
	 */
	public void setPreferredUsername(final String preferredUsername) {
	
		setClaim("preferred_username", preferredUsername);
	}
	
	
	/**
	 * Gets the profile page. Corresponds to the {@code profile} claim.
	 *
	 * @return The profile page URL, {@code null} if not specified.
	 */
	public URL getProfile() {
	
		return getURLClaim("profile");
	}
	
	
	/**
	 * Sets the profile page. Corresponds to the {@code profile} claim.
	 *
	 * @param profile The profile page URL. If {@code null} the claim will
	 *                be removed.
	 */
	public void setProfile(final URL profile) {
	
		setURLClaim("profile", profile);
	}
	
	
	/**
	 * Gets the picture. Corresponds to the {@code picture} claim.
	 *
	 * @return The picture URL, {@code null} if not specified.
	 */
	public URL getPicture() {
	
		return getURLClaim("picture");
	}
	
	
	/**
	 * Sets the picture. Corresponds to the {@code picture} claim.
	 *
	 * @param picture The picture URL. If {@code null} the claim will be
	 *                removed.
	 */
	public void setPicture(final URL picture) {
	
		setURLClaim("picture", picture);
	}
	
	
	/**
	 * Gets the web page or blog. Corresponds to the {@code website} claim.
	 *
	 * @return The web page or blog URL, {@code null} if not specified.
	 */
	public URL getWebsite() {
	
		return getURLClaim("website");
	}
	
	
	/**
	 * Sets the web page or blog. Corresponds to the {@code website} claim.
	 *
	 * @param website The web page or blog URL. If {@code null} the claim
	 *                will be removed.
	 */
	public void setWebsite(final URL website) {
	
		setURLClaim("website", website);
	}
	
	
	/**
	 * Gets the preferred email address. Corresponds to the {@code email} 
	 * claim.
	 *
	 * @return The preferred email address, {@code null} if not specified.
	 */
	public InternetAddress getEmail() {
	
		return getEmailClaim("email");
	}
	
	
	/**
	 * Sets the preferred email address. Corresponds to the {@code email}
	 * claim.
	 *
	 * @param email The preferred email address. If {@code null} the claim
	 *              will be removed.
	 */
	public void setEmail(final InternetAddress email) {
	
		setEmailClaim("email", email);
	}
	
	
	/**
	 * Gets the email verification status. Corresponds to the 
	 * {@code email_verified} claim.
	 *
	 * @return The email verification status, {@code null} if not 
	 *         specified.
	 */
	public Boolean getEmailVerified() {
	
		return getBooleanClaim("email_verified");
	}
	
	
	/**
	 * Sets the email verification status. Corresponds to the
	 * {@code email_verified} claim.
	 *
	 * @param emailVerified The email verification status. If {@code null} 
	 *                      the claim will be removed.
	 */
	public void setEmailVerified(final Boolean emailVerified) {
	
		setClaim("email_verified", emailVerified);
	}
	
	
	/**
	 * Gets the gender. Corresponds to the {@code gender} claim.
	 *
	 * @return The gender, {@code null} if not specified.
	 */
	public Gender getGender() {
	
		String value = getStringClaim("gender");
		
		if (value == null)
			return null;

		return new Gender(value);
	}
	
	
	/**
	 * Sets the gender. Corresponds to the {@code gender} claim.
	 *
	 * @param gender The gender. If {@code null} the claim will be removed.
	 */
	public void setGender(final Gender gender) {
	
		if (gender != null)
			setClaim("gender", gender.getValue());
		else
			setClaim("gender", null);
	}
	
	
	/**
	 * Gets the date of birth. Corresponds to the {@code birthdate} claim.
	 *
	 * @return The date of birth, {@code null} if not specified.
	 */
	public String getBirthdate() {
	
		return getStringClaim("birthdate");
	}
	
	
	/**
	 * Sets the date of birth. Corresponds to the {@code birthdate} claim.
	 *
	 * @param birthdate The date of birth. If {@code null} the claim will
	 *                  be removed.
	 */
	public void setBirthdate(final String birthdate) {
	
		setClaim("birthdate", birthdate);
	}
	
	
	/**
	 * Gets the zoneinfo. Corresponds to the {@code zoneinfo} claim.
	 *
	 * @return The zoneinfo, {@code null} if not specified.
	 */
	public String getZoneinfo() {
	
		return getStringClaim("zoneinfo");
	}
	
	
	/**
	 * Sets the zoneinfo. Corresponds to the {@code zoneinfo} claim.
	 *
	 * @param zoneinfo The zoneinfo. If {@code null} the claim will be 
	 *                 removed.
	 */
	public void setZoneinfo(final String zoneinfo) {
	
		setClaim("zoneinfo", zoneinfo);
	}
	
	
	/**
	 * Gets the locale. Corresponds to the {@code locale} claim.
	 *
	 * @return The locale, {@code null} if not specified.
	 */
	public String getLocale() {
	
		return getStringClaim("locale");
	}
	
	
	/**
	 * Sets the locale. Corresponds to the {@code locale} claim.
	 *
	 * @param locale The locale. If {@code null} the claim will be 
	 *               removed.
	 */
	public void setLocale(final String locale) {
	
		setClaim("locale", locale);
	}
	
	
	/**
	 * Gets the preferred telephone number. Corresponds to the 
	 * {@code phone_number} claim.
	 *
	 * @return The preferred telephone number, {@code null} if not 
	 *         specified.
	 */
	public String getPhoneNumber() {
	
		return getStringClaim("phone_number");
	}
	
	
	/**
	 * Sets the preferred telephone number. Corresponds to the 
	 * {@code phone_number} claim.
	 *
	 * @param phoneNumber The preferred telephone number. If {@code null} 
	 *                    the claim will be removed.
	 */
	public void setPhoneNumber(final String phoneNumber) {
	
		setClaim("phone_number", phoneNumber);
	}
	
	
	/**
	 * Gets the phone number verification status. Corresponds to the 
	 * {@code phone_number_verified} claim.
	 *
	 * @return The phone number verification status, {@code null} if not 
	 *         specified.
	 */
	public Boolean getPhoneNumberVerified() {
	
		return getBooleanClaim("phone_number_verified");
	}
	
	
	/**
	 * Sets the email verification status. Corresponds to the
	 * {@code phone_number_verified} claim.
	 *
	 * @param phoneNumberVerified The phone number verification status. If 
	 *                            {@code null} the claim will be removed.
	 */
	public void setPhoneNumberVerified(final Boolean phoneNumberVerified) {
	
		setClaim("phone_number_verified", phoneNumberVerified);
	}


	/**
	 * Gets the preferred address. Corresponds to the {@code address} 
	 * claim, with no language tag.
	 *
	 * @return The preferred address, {@code null} if not specified.
	 */
	public Address getAddress() {
	
		return getAddress(null);
	}
	
	
	/**
	 * Gets the preferred address. Corresponds to the {@code address} 
	 * claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The preferred address, {@code null} if not specified.
	 */
	public Address getAddress(final LangTag langTag) {
	
		String name;

		if (langTag!= null)
			name = "address#" + langTag;
		else
			name = "address";

		JSONObject jsonObject = getClaim(name, JSONObject.class);

		if (jsonObject == null)
			return null;

		return new Address(jsonObject);
	}
	
	
	/**
	 * Gets the preferred address entries. Correspond to the 
	 * {@code address} claim.
	 *
	 * @return The preferred address entries, empty map if none.
	 */
	public Map<LangTag,Address> getAddressEntries() {
	
		Map<LangTag,JSONObject> entriesIn = getLangTaggedClaim("address", JSONObject.class);

		Map<LangTag,Address> entriesOut = new HashMap<LangTag,Address>();

		for (Map.Entry<LangTag,JSONObject> en: entriesIn.entrySet())
			entriesOut.put(en.getKey(), new Address(en.getValue()));

		return entriesOut;
	}


	/**
	 * Sets the preferred address. Corresponds to the {@code address} 
	 * claim, with no language tag.
	 *
	 * @param address The preferred address. If {@code null} the claim will
	 *                be removed.
	 */
	public void setAddress(final Address address) {
	
		if (address != null)
			setClaim("address", address.getJSONObject());
		else
			setClaim("address", null);
	}
	
	
	/**
	 * Sets the preferred address. Corresponds to the {@code address}
	 * claim, with an optional language tag.
	 *
	 * @param address  The preferred address. If {@code null} the claim 
	 *                 will be removed.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setAddress(final Address address, final LangTag langTag) {

		String key = langTag == null ? "address" : "address#" + langTag;

		if (address != null)
			setClaim(key, address.getJSONObject());
		else
			setClaim(key, null);
	}
	
	
	/**
	 * Gets the time the end-user information was last updated. Corresponds 
	 * to the {@code updated_at} claim.
	 *
	 * @return The time the end-user information was last updated, 
	 *         {@code null} if not specified.
	 */
	public Date getUpdatedTime() {
	
		return getDateClaim("updated_at");
	}
	
	
	/**
	 * Sets the time the end-user information was last updated. Corresponds
	 * to the {@code updated_at} claim.
	 *
	 * @param updatedTime The time the end-user information was last 
	 *                    updated. If {@code null} the claim will be 
	 *                    removed.
	 */
	public void setUpdatedTime(final Date updatedTime) {
	
		setDateClaim("updated_at", updatedTime);
	}
}
