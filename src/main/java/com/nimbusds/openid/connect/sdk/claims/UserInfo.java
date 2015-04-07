package com.nimbusds.openid.connect.sdk.claims;


import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.jwt.JWTClaimsSet;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


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
 *     <li>OpenID Connect Core 1.0, section 5.1.
 * </ul>
 */
public class UserInfo extends ClaimsSet {


	/**
	 * The subject claim name.
	 */
	public static final String SUB_CLAIM_NAME = "sub";


	/**
	 * The name claim name.
	 */
	public static final String NAME_CLAIM_NAME = "name";


	/**
	 * The given name claim name.
	 */
	public static final String GIVEN_NAME_CLAIM_NAME = "given_name";


	/**
	 * The family name claim name.
	 */
	public static final String FAMILY_NAME_CLAIM_NAME = "family_name";


	/**
	 * The middle name claim name.
	 */
	public static final String MIDDLE_NAME_CLAIM_NAME = "middle_name";


	/**
	 * The nickname claim name.
	 */
	public static final String NICKNAME_CLAIM_NAME = "nickname";


	/**
	 * The preferred username claim name.
	 */
	public static final String PREFERRED_USERNAME_CLAIM_NAME = "preferred_username";


	/**
	 * The profile claim name.
	 */
	public static final String PROFILE_CLAIM_NAME = "profile";


	/**
	 * The picture claim name.
	 */
	public static final String PICTURE_CLAIM_NAME = "picture";


	/**
	 * The website claim name.
	 */
	public static final String WEBSITE_CLAIM_NAME = "website";


	/**
	 * The email claim name.
	 */
	public static final String EMAIL_CLAIM_NAME = "email";


	/**
	 * The email verified claim name.
	 */
	public static final String EMAIL_VERIFIED_CLAIM_NAME = "email_verified";


	/**
	 * The gender claim name.
	 */
	public static final String GENDER_CLAIM_NAME = "gender";


	/**
	 * The birth date claim name.
	 */
	public static final String BIRTHDATE_CLAIM_NAME = "birthdate";


	/**
	 * The zoneinfo claim name.
	 */
	public static final String ZONEINFO_CLAIM_NAME = "zoneinfo";


	/**
	 * The locale claim name.
	 */
	public static final String LOCALE_CLAIM_NAME = "locale";


	/**
	 * The phone number claim name.
	 */
	public static final String PHONE_NUMBER_CLAIM_NAME = "phone_number";


	/**
	 * The phone number verified claim name.
	 */
	public static final String PHONE_NUMBER_VERIFIED_CLAIM_NAME = "phone_number_verified";


	/**
	 * The address claim name.
	 */
	public static final String ADDRESS_CLAIM_NAME = "address";


	/**
	 * The updated at claim name.
	 */
	public static final String UPDATED_AT_CLAIM_NAME = "updated_at";


	/**
	 * The names of the standard top-level UserInfo claims.
	 */
	private static final Set<String> stdClaimNames = new LinkedHashSet<>();
	
	
	static {
		stdClaimNames.add(SUB_CLAIM_NAME);
		stdClaimNames.add(NAME_CLAIM_NAME);
		stdClaimNames.add(GIVEN_NAME_CLAIM_NAME);
		stdClaimNames.add(FAMILY_NAME_CLAIM_NAME);
		stdClaimNames.add(MIDDLE_NAME_CLAIM_NAME);
		stdClaimNames.add(NICKNAME_CLAIM_NAME);
		stdClaimNames.add(PREFERRED_USERNAME_CLAIM_NAME);
		stdClaimNames.add(PROFILE_CLAIM_NAME);
		stdClaimNames.add(PICTURE_CLAIM_NAME);
		stdClaimNames.add(WEBSITE_CLAIM_NAME);
		stdClaimNames.add(EMAIL_CLAIM_NAME);
		stdClaimNames.add(EMAIL_VERIFIED_CLAIM_NAME);
		stdClaimNames.add(GENDER_CLAIM_NAME);
		stdClaimNames.add(BIRTHDATE_CLAIM_NAME);
		stdClaimNames.add(ZONEINFO_CLAIM_NAME);
		stdClaimNames.add(LOCALE_CLAIM_NAME);
		stdClaimNames.add(PHONE_NUMBER_CLAIM_NAME);
		stdClaimNames.add(PHONE_NUMBER_VERIFIED_CLAIM_NAME);
		stdClaimNames.add(ADDRESS_CLAIM_NAME);
		stdClaimNames.add(UPDATED_AT_CLAIM_NAME);
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
	
		setClaim(SUB_CLAIM_NAME, sub.getValue());
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

		if (getStringClaim(SUB_CLAIM_NAME) == null)
			throw new IllegalArgumentException("Missing or invalid \"sub\" claim");
	}


	/**
	 * Creates a new UserInfo claims set from the specified JSON Web Token
	 * (JWT) claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the JWT claims set doesn't
	 *                                  contain a subject {@code sub}
	 *                                  string claim.
	 */
	public UserInfo(final JWTClaimsSet jwtClaimsSet) {

		this(jwtClaimsSet.toJSONObject());
	}


	/**
	 * Puts all claims from the specified other UserInfo claims set.
	 *
	 * @param other The other UserInfo. Must have the same
	 *              {@link #getSubject subject}. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the other UserInfo claims set
	 *                                  doesn't have an identical subject.
	 */
	public void putAll(final UserInfo other) {

		Subject otherSubject = other.getSubject();

		if (otherSubject == null)
			throw new IllegalArgumentException("The subject of the other UserInfo is missing");

		if (! otherSubject.equals(getSubject()))
			throw new IllegalArgumentException("The subject of the other UserInfo must be identical");

		putAll((ClaimsSet)other);
	}
	
	
	/**
	 * Gets the UserInfo subject. Corresponds to the {@code sub} claim.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {
	
		return new Subject(getStringClaim(SUB_CLAIM_NAME));
	}

	
	/**
	 * Gets the full name. Corresponds to the {@code name} claim, with no
	 * language tag.
	 *
	 * @return The full name, {@code null} if not specified.
	 */
	public String getName() {
	
		return getStringClaim(NAME_CLAIM_NAME);
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
	
		return getStringClaim(NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the full name entries. Correspond to the {@code name} claim.
	 *
	 * @return The full name entries, empty map if none.
	 */
	public Map<LangTag,String> getNameEntries() {
	
		return getLangTaggedClaim(NAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the full name. Corresponds to the {@code name} claim, with no
	 * language tag.
	 *
	 * @param name The full name. If {@code null} the claim will be 
	 *             removed.
	 */
	public void setName(final String name) {
	
		setClaim(NAME_CLAIM_NAME, name);
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
	
		setClaim(NAME_CLAIM_NAME, name, langTag);
	}	
	
	
	/**
	 * Gets the given or first name. Corresponds to the {@code given_name} 
	 * claim, with no language tag.
	 *
	 * @return The given or first name, {@code null} if not specified.
	 */
	public String getGivenName() {
	
		return getStringClaim(GIVEN_NAME_CLAIM_NAME);
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
	
		return getStringClaim(GIVEN_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the given or first name entries. Correspond to the 
	 * {@code given_name} claim.
	 *
	 * @return The given or first name entries, empty map if none.
	 */
	public Map<LangTag,String> getGivenNameEntries() {
	
		return getLangTaggedClaim(GIVEN_NAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the given or first name. Corresponds to the {@code given_name} 
	 * claim, with no language tag.
	 *
	 * @param givenName The given or first name. If {@code null} the claim
	 *                  will be removed.
	 */
	public void setGivenName(final String givenName) {
	
		setClaim(GIVEN_NAME_CLAIM_NAME, givenName);
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
	
		setClaim(GIVEN_NAME_CLAIM_NAME, givenName, langTag);
	}

	
	/**
	 * Gets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with no language tag.
	 *
	 * @return The surname or last name, {@code null} if not specified.
	 */
	public String getFamilyName() {
	
		return getStringClaim(FAMILY_NAME_CLAIM_NAME);
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
	
		return getStringClaim(FAMILY_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the surname or last name entries. Correspond to the 
	 * @code family_name} claim.
	 *
	 * @return The surname or last name entries, empty map if none.
	 */
	public Map<LangTag,String> getFamilyNameEntries() {
	
		return getLangTaggedClaim(FAMILY_NAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with no language tag.
	 *
	 * @param familyName The surname or last name. If {@code null} the 
	 *                   claim will be removed.
	 */
	public void setFamilyName(final String familyName) {
	
		setClaim(FAMILY_NAME_CLAIM_NAME, familyName);
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
	
		setClaim(FAMILY_NAME_CLAIM_NAME, familyName, langTag);
	}

	
	/**
	 * Gets the middle name. Corresponds to the {@code middle_name} claim, 
	 * with no language tag.
	 *
	 * @return The middle name, {@code null} if not specified.
	 */
	public String getMiddleName() {
	
		return getStringClaim(MIDDLE_NAME_CLAIM_NAME);
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
	
		return getStringClaim(MIDDLE_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the middle name entries. Correspond to the {@code middle_name}
	 * claim.
	 *
	 * @return The middle name entries, empty map if none.
	 */
	public Map<LangTag,String> getMiddleNameEntries() {
	
		return getLangTaggedClaim(MIDDLE_NAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the middle name. Corresponds to the {@code middle_name} claim,
	 * with no language tag.
	 *
	 * @param middleName The middle name. If {@code null} the claim will be
	 *                   removed.
	 */
	public void setMiddleName(final String middleName) {
	
		setClaim(MIDDLE_NAME_CLAIM_NAME, middleName);
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
	
		setClaim(MIDDLE_NAME_CLAIM_NAME, middleName, langTag);
	}
	
	
	/**
	 * Gets the casual name. Corresponds to the {@code nickname} claim, 
	 * with no language tag.
	 *
	 * @return The casual name, {@code null} if not specified.
	 */
	public String getNickname() {
	
		return getStringClaim(NICKNAME_CLAIM_NAME);
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
	
		return getStringClaim(NICKNAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the casual name entries. Correspond to the {@code nickname} 
	 * claim.
	 *
	 * @return The casual name entries, empty map if none.
	 */
	public Map<LangTag,String> getNicknameEntries() {
	
		return getLangTaggedClaim(NICKNAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the casual name. Corresponds to the {@code nickname} claim, 
	 * with no language tag.
	 *
	 * @param nickname The casual name. If {@code null} the claim will be
	 *                 removed.
	 */
	public void setNickname(final String nickname) {
	
		setClaim(NICKNAME_CLAIM_NAME, nickname);
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
	
		setClaim(NICKNAME_CLAIM_NAME, nickname, langTag);
	}
	
	
	/**
	 * Gets the preferred username. Corresponds to the 
	 * {@code preferred_username} claim.
	 *
	 * @return The preferred username, {@code null} if not specified.
	 */
	public String getPreferredUsername() {
	
		return getStringClaim(PREFERRED_USERNAME_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the preferred username. Corresponds to the 
	 * {@code preferred_username} claim.
	 *
	 * @param preferredUsername The preferred username. If {@code null} the
	 *                          claim will be removed.
	 */
	public void setPreferredUsername(final String preferredUsername) {
	
		setClaim(PREFERRED_USERNAME_CLAIM_NAME, preferredUsername);
	}
	
	
	/**
	 * Gets the profile page. Corresponds to the {@code profile} claim.
	 *
	 * @return The profile page URI, {@code null} if not specified.
	 */
	public URI getProfile() {
	
		return getURIClaim(PROFILE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the profile page. Corresponds to the {@code profile} claim.
	 *
	 * @param profile The profile page URI. If {@code null} the claim will
	 *                be removed.
	 */
	public void setProfile(final URI profile) {
	
		setURIClaim(PROFILE_CLAIM_NAME, profile);
	}
	
	
	/**
	 * Gets the picture. Corresponds to the {@code picture} claim.
	 *
	 * @return The picture URI, {@code null} if not specified.
	 */
	public URI getPicture() {
	
		return getURIClaim(PICTURE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the picture. Corresponds to the {@code picture} claim.
	 *
	 * @param picture The picture URI. If {@code null} the claim will be
	 *                removed.
	 */
	public void setPicture(final URI picture) {
	
		setURIClaim(PICTURE_CLAIM_NAME, picture);
	}
	
	
	/**
	 * Gets the web page or blog. Corresponds to the {@code website} claim.
	 *
	 * @return The web page or blog URI, {@code null} if not specified.
	 */
	public URI getWebsite() {
	
		return getURIClaim(WEBSITE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the web page or blog. Corresponds to the {@code website} claim.
	 *
	 * @param website The web page or blog URI. If {@code null} the claim
	 *                will be removed.
	 */
	public void setWebsite(final URI website) {
	
		setURIClaim(WEBSITE_CLAIM_NAME, website);
	}
	
	
	/**
	 * Gets the preferred email address. Corresponds to the {@code email} 
	 * claim.
	 *
	 * @return The preferred email address, {@code null} if not specified.
	 */
	public InternetAddress getEmail() {
	
		return getEmailClaim(EMAIL_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the preferred email address. Corresponds to the {@code email}
	 * claim.
	 *
	 * @param email The preferred email address. If {@code null} the claim
	 *              will be removed.
	 */
	public void setEmail(final InternetAddress email) {
	
		setEmailClaim(EMAIL_CLAIM_NAME, email);
	}
	
	
	/**
	 * Gets the email verification status. Corresponds to the 
	 * {@code email_verified} claim.
	 *
	 * @return The email verification status, {@code null} if not 
	 *         specified.
	 */
	public Boolean getEmailVerified() {
	
		return getBooleanClaim(EMAIL_VERIFIED_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the email verification status. Corresponds to the
	 * {@code email_verified} claim.
	 *
	 * @param emailVerified The email verification status. If {@code null} 
	 *                      the claim will be removed.
	 */
	public void setEmailVerified(final Boolean emailVerified) {
	
		setClaim(EMAIL_VERIFIED_CLAIM_NAME, emailVerified);
	}
	
	
	/**
	 * Gets the gender. Corresponds to the {@code gender} claim.
	 *
	 * @return The gender, {@code null} if not specified.
	 */
	public Gender getGender() {
	
		String value = getStringClaim(GENDER_CLAIM_NAME);
		
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
			setClaim(GENDER_CLAIM_NAME, gender.getValue());
		else
			setClaim(GENDER_CLAIM_NAME, null);
	}
	
	
	/**
	 * Gets the date of birth. Corresponds to the {@code birthdate} claim.
	 *
	 * @return The date of birth, {@code null} if not specified.
	 */
	public String getBirthdate() {
	
		return getStringClaim(BIRTHDATE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the date of birth. Corresponds to the {@code birthdate} claim.
	 *
	 * @param birthdate The date of birth. If {@code null} the claim will
	 *                  be removed.
	 */
	public void setBirthdate(final String birthdate) {
	
		setClaim(BIRTHDATE_CLAIM_NAME, birthdate);
	}
	
	
	/**
	 * Gets the zoneinfo. Corresponds to the {@code zoneinfo} claim.
	 *
	 * @return The zoneinfo, {@code null} if not specified.
	 */
	public String getZoneinfo() {
	
		return getStringClaim(ZONEINFO_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the zoneinfo. Corresponds to the {@code zoneinfo} claim.
	 *
	 * @param zoneinfo The zoneinfo. If {@code null} the claim will be 
	 *                 removed.
	 */
	public void setZoneinfo(final String zoneinfo) {
	
		setClaim(ZONEINFO_CLAIM_NAME, zoneinfo);
	}
	
	
	/**
	 * Gets the locale. Corresponds to the {@code locale} claim.
	 *
	 * @return The locale, {@code null} if not specified.
	 */
	public String getLocale() {
	
		return getStringClaim(LOCALE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the locale. Corresponds to the {@code locale} claim.
	 *
	 * @param locale The locale. If {@code null} the claim will be 
	 *               removed.
	 */
	public void setLocale(final String locale) {
	
		setClaim(LOCALE_CLAIM_NAME, locale);
	}
	
	
	/**
	 * Gets the preferred telephone number. Corresponds to the 
	 * {@code phone_number} claim.
	 *
	 * @return The preferred telephone number, {@code null} if not 
	 *         specified.
	 */
	public String getPhoneNumber() {
	
		return getStringClaim(PHONE_NUMBER_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the preferred telephone number. Corresponds to the 
	 * {@code phone_number} claim.
	 *
	 * @param phoneNumber The preferred telephone number. If {@code null} 
	 *                    the claim will be removed.
	 */
	public void setPhoneNumber(final String phoneNumber) {
	
		setClaim(PHONE_NUMBER_CLAIM_NAME, phoneNumber);
	}
	
	
	/**
	 * Gets the phone number verification status. Corresponds to the 
	 * {@code phone_number_verified} claim.
	 *
	 * @return The phone number verification status, {@code null} if not 
	 *         specified.
	 */
	public Boolean getPhoneNumberVerified() {
	
		return getBooleanClaim(PHONE_NUMBER_VERIFIED_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the email verification status. Corresponds to the
	 * {@code phone_number_verified} claim.
	 *
	 * @param phoneNumberVerified The phone number verification status. If 
	 *                            {@code null} the claim will be removed.
	 */
	public void setPhoneNumberVerified(final Boolean phoneNumberVerified) {
	
		setClaim(PHONE_NUMBER_VERIFIED_CLAIM_NAME, phoneNumberVerified);
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
			name = ADDRESS_CLAIM_NAME + "#" + langTag;
		else
			name = ADDRESS_CLAIM_NAME;

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
	
		Map<LangTag,JSONObject> entriesIn = getLangTaggedClaim(ADDRESS_CLAIM_NAME, JSONObject.class);

		Map<LangTag,Address> entriesOut = new HashMap<>();

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
			setClaim(ADDRESS_CLAIM_NAME, address.toJSONObject());
		else
			setClaim(ADDRESS_CLAIM_NAME, null);
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

		String key = langTag == null ? ADDRESS_CLAIM_NAME : ADDRESS_CLAIM_NAME + "#" + langTag;

		if (address != null)
			setClaim(key, address.toJSONObject());
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
	
		return getDateClaim(UPDATED_AT_CLAIM_NAME);
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
	
		setDateClaim(UPDATED_AT_CLAIM_NAME, updatedTime);
	}


	/**
	 * Parses a UserInfo claims set from the specified JSON object string.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The UserInfo claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static UserInfo parse(final String json)
		throws ParseException {

		JSONObject jsonObject = JSONObjectUtils.parse(json);

		try {
			return new UserInfo(jsonObject);

		} catch (IllegalArgumentException e) {

			throw new ParseException(e.getMessage(), e);
		}
	}
}
