package com.nimbusds.openid.connect.messages;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.claims.GenericClaim;
import com.nimbusds.openid.connect.claims.UserID;
import com.nimbusds.openid.connect.claims.UserInfo;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * UserInfo claims, serialisable to a JSON object.
 *
 * <p>Example UserInfo claims set:
 *
 * <pre>
 * {
 *   "user_id"     : "248289761001",
 *   "name"        : "Jane Doe",
 *   "given_name"  : "Jane",
 *   "family_name" : "Doe",
 *   "email"       : "janedoe@example.com",
 *   "picture"     : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * <p>See http://openid.net/specs/openid-connect-messages-1_0.html#anchor14
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-16)
 */
public class UserInfoClaims extends JSONObjectClaims {


	/**
	 * The names of the reserved top-level UserInfo claims.
	 */
	private static final Set<String> reservedClaimNames = new HashSet<String>();
	
	
	static {
		reservedClaimNames.add("user_id");
		reservedClaimNames.add("name");
		reservedClaimNames.add("given_name");
		reservedClaimNames.add("family_name");
		reservedClaimNames.add("middle_name");
		reservedClaimNames.add("nickname");
		reservedClaimNames.add("profile");
		reservedClaimNames.add("picture");
		reservedClaimNames.add("website");
		reservedClaimNames.add("email");
		reservedClaimNames.add("verified");
		reservedClaimNames.add("gender");
		reservedClaimNames.add("birthday");
		reservedClaimNames.add("zoneinfo");
		reservedClaimNames.add("locale");
		reservedClaimNames.add("phone_number");
		reservedClaimNames.add("address");
		reservedClaimNames.add("updated_time");
	}
	
	
	/**
	 * Gets the names of the reserved top-level UserInfo claims.
	 *
	 * @return The names of the reserved top-level UserInfo claims 
	 * (read-only set).
	 */
	public static Set<String> getReservedClaimNames() {
	
		return Collections.unmodifiableSet(reservedClaimNames);
	}
	
	
	/**
	 * The user ID (required).
	 */
	private UserID userID;
	
	
	/**
	 * The full name (optional).
	 */
	private UserInfo.Name name = null;
	
	
	/**
	 * The given name or first name (optional).
	 */
	private UserInfo.GivenName givenName = null;
	
	
	/**
	 * The surname or last name (optional).
	 */
	private UserInfo.FamilyName familyName = null;
	
	
	/**
	 * The middle name (optional).
	 */
	private UserInfo.MiddleName middleName = null;
	
	
	/**
	 * The casual name (optional).
	 */
	private UserInfo.Nickname nickname = null;
	
	
	/**
	 * The profile page URL (optional).
	 */
	private UserInfo.Profile profile = null;
	
	
	/**
	 * The picture URL (optional).
	 */
	private UserInfo.Picture picture = null;
	
	
	/**
	 * The web page or blog URL (optional).
	 */
	private UserInfo.Website website = null;
	
	
	/**
	 * The preferred email address (optional).
	 */
	private UserInfo.Email email = null;
	
	
	/**
	 * {@code true} if the email address has been verified, otherwise
	 * {@code false}.
	 */
	private UserInfo.Verified verified = null;
	
	
	/**
	 * The gender (optional).
	 */
	private UserInfo.Gender gender = null;
	
	
	/**
	 * The birthday (optional).
	 */
	private UserInfo.Birthday birthday = null;
	
	
	/**
	 * The zoneinfo (optional).
	 */
	private UserInfo.Zoneinfo zoneinfo = null;
	
	
	/**
	 * The locale (optional).
	 */
	private UserInfo.Locale locale = null;
	
	
	/**
	 * The preferred telephone number (optional).
	 */
	private UserInfo.PhoneNumber phoneNumber = null;
	
	
	/**
	 * Time the end-user information was last updated (optional).
	 */
	private UserInfo.UpdatedTime updatedTime = null;
	
	
	/**
	 * @inheritDoc
	 */
	public void addCustomClaim(final GenericClaim customClaim) {
	
		if (reservedClaimNames.contains(customClaim.getClaimName()))
			throw new IllegalArgumentException("Custom claim name conflicts with reserved claim name: " + customClaim.getClaimName());
	
		customClaims.put(customClaim.getClaimName(), customClaim);
	}
	
	
	/**
	 * @inheritDoc
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("user_id", userID.getClaimValue());
		
		if (name != null)
			o.put("name", name.getClaimValue());
		
		return o;
	}
}
