package com.nimbusds.openid.connect.sdk.claims;


import java.net.URL;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

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
 *     <li>OpenID Connect Messages 1.0, section 2.4.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-22)
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
		stdClaimNames.add("address");
		stdClaimNames.add("updated_time");
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
	 * Creates a new minimal UserInfo claims set. Any optional claims are
	 * specified with the setter methods.
	 *
	 * @param sub The subject. Must not be {@code null}.
	 */
	public UserInfo(final Subject sub) {
	
		if (sub == null)
			throw new IllegalArgumentException("The subject must not be null");

		setStringClaim("sub", sub.getValue());
	}
	
	
	/**
	 * Gets the UserInfo subject. Corresponds to the {@code sub} claim.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {
	
		String value = getStringClaim("sub");

		if (value != null)
			return new Subject(value);
		else
			return null;
	}


	

////////////////////////////////////////////////////////////////////////////////
	
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
	
		if (langTag == null)
			return getStringClaim("name");

		else
			return getStringClaim("name#" + langTag);
	}
	
	
	/**
	 * Gets the full name entries. Correspond to the {@code name} claim.
	 *
	 * @return The full name entries, empty map if none.
	 */
	public Map<LangTag,String> getNameEntries() {
	
		return getLangTaggedStringClaims("name");
	}


	/**
	 * Sets the full name. Corresponds to the {@code name} claim, with no
	 * language tag.
	 *
	 * @param name The full name. {@code null} if not specified.
	 */
	public void setName(final String name) {
	
		setStringClaim("name", name);
	}
	
	
	/**
	 * Sets the full name. Corresponds to the {@code name} claim, with an
	 * optional language tag.
	 *
	 * @param name The full name, with optional language tag. {@code null}
	 *             if not specified.
	 */
	public void setName(final LangTaggedObject<String> name) {
	
		setStringClaim("name", name);
	}

////////////////////////////////////////////////////////////////////////////////	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
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
	 * @param preferredUsername The preferred username, {@code null} if not 
	 *                          specified.
	 */
	public void setPreferredUsername(final String preferredUsername) {
	
		setStringClaim("preferred_username", preferredUsername);
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
	 * @param profile The profile page URL, {@code null} if not specified.
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
	 * @param picture The picture URL, {@code null} if not specified.
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
	 * @param website The web page or blog URL, {@code null} if not 
	 *                specified.
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
	 * @param email The preferred email address, {@code null} if not
	 *              specified.
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
	 * @param emailVerified The email verification status, {@code null} if 
	 *                      not specified.
	 */
	public void setEmailVerified(final Boolean emailVerified) {
	
		setBooleanClaim("email_verified", emailVerified);
	}
	
	
	/**
	 * Gets the gender. Corresponds to the {@code gender} claim.
	 *
	 * @return The gender, {@code null} if not specified.
	 */
	public Gender getGender() {
	
		String value = getStringClaim("gender");

		if (value != null)
			return new Gender(value);
		else
			return null;
	}
	
	
	/**
	 * Sets the gender. Corresponds to the {@code gender} claim.
	 *
	 * @param gender The gender, {@code null} if not specified.
	 */
	public void setGender(final Gender gender) {
	
		if (gender != null)
			setStringClaim("gender", gender.getValue());
		else
			setStringClaim("gender", (String)null);
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
	 * @param birthdate The date of birth, {@code null} if not specified.
	 */
	public void setBirthdate(final String birthdate) {
	
		setStringClaim("birthdate", birthdate);
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
	 * @param zoneinfo The zoneinfo, {@code null} if not specified.
	 */
	public void setZoneinfo(final String zoneinfo) {
	
		setStringClaim("zoneinfo", zoneinfo);
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
	 * @param locale The locale, {@code null} if not specified.
	 */
	public void setLocale(final String locale) {
	
		setStringClaim("locale", locale);
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
	 * @param phoneNumber The preferred telephone number, {@code null} if
	 *                    not specified.
	 */
	public void setPhoneNumber(final String phoneNumber) {
	
		setStringClaim("phone_number", phoneNumber);
	}
	
	
	/**
	 * Adds the specified preferred address, with optional language tag.
	 * Corresponds to the {@code address} claim.
	 *
	 * @param address The preferred address, with optional language tag.
	 *                {@code null} if not specified.
	 */
	public void addAddress(final Object address) {
	
		
	}
	
	
	/**
	 * Gets the preferred address with no language tag. Corresponds to the 
	 * {@code address} claim.
	 *
	 * @return The preferred address with no language tag, {@code null} if 
	 *         not specified.
	 */
	public Object getAddress() {
	
		return null;
	}
	
	
	/**
	 * Gets the preferred address with the specified language tag. 
	 * Corresponds to the {@code address} claim.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get the
	 *                untagged entry.
	 *
	 * @return The preferred address, {@code null} if not specified.
	 */
	public Object getAddress(final LangTag langTag) {
	
		return null;
	}
	
	
	/**
	 * Gets the time the end-user information was last updated. Corresponds 
	 * to the {@code updated_time} claim.
	 *
	 * @return The time the end-user information was last updated, 
	 *         {@code null} if not specified.
	 */
	public String getUpdatedTime() {
	
		return getStringClaim("updated_time");
	}
	
	
	/**
	 * Sets the time the end-user information was last updated. Corresponds
	 * to the {@code updated_time} claim.
	 *
	 * @param updatedTime The time the end-user information was last 
	 *                    updated, {@code null} if not specified.
	 */
	public void setUpdatedTime(final String updatedTime) {
	
		setStringClaim("updated_time", updatedTime);
	}
	
	
	/**
	 * Parses a UserInfo claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The UserInfo claims set.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        valid UserInfo authentication claims set.
	 */
	public static UserInfo parse(final JSONObject jsonObject)
		throws ParseException {
		
		Subject sub = new Subject("xyz");

		
		
		return null;
	}
}
