package com.nimbusds.openid.connect.claims;


import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * UserInfo address claims, serialisable to a JSON object.
 *
 * <p>Example UserInfo address claims set:
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
 * <p>See http://openid.net/specs/openid-connect-messages-1_0.html#address_claim
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-16)
 */
public class AddressClaims extends JSONObjectClaims {


	/**
	 * The names of the reserved UserInfo address claims.
	 */
	private static final Set<String> reservedClaimNames = new HashSet<String>();
	
	
	static {
		reservedClaimNames.add("formatted");
		reservedClaimNames.add("street_address");
		reservedClaimNames.add("locality");
		reservedClaimNames.add("region");
		reservedClaimNames.add("postal_code");
		reservedClaimNames.add("country");
	}
	
	
	/**
	 * Gets the names of the reserved UserInfo addres claims.
	 *
	 * @return The names of the reserved address claims (read-only set).
	 */
	public static Set<String> getReservedClaimNames() {
	
		return Collections.unmodifiableSet(reservedClaimNames);
	}
	
	
	/**
	 * The full mailing address, formatted for display or use with a mailing
	 * label (optional).
	 */
	private UserInfo.Address.Formatted formatted = null;
	
	
	/**
	 * The full street address component, which may include house number, 
	 * street name, PO BOX, and multi-line extended street address 
	 * information (optional).
	 */
	private UserInfo.Address.StreetAddress streetAddress = null;
	
	
	/**
	 * The city or locality component (optional).
	 */
	private UserInfo.Address.Locality locality = null;
	
	
	/**
	 * The state, province, prefecture or region component (optional).
	 */
	private UserInfo.Address.Region region = null;
	
	
	/**
	 * The zip code or postal code component (optional).
	 */
	private UserInfo.Address.PostalCode postalCode = null;
	
	
	/**
	 * The country name component (optional).
	 */
	private UserInfo.Address.Country country = null;
	
	
	/**
	 * Creates a new minimal (empty) UserInfo address claims set. Use the 
	 * setter methods for the optional claims (all).
	 */
	public AddressClaims() {
	
		// Nothing
	}
	
	
	/**
	 * Gets the full mailing address, formatted for display or use with a
	 * mailing label. May contain newlines. Corresponds to the
	 * {@code formatted} claim.
	 *
	 * @return The full mailing address, {@code null} if not specified.
	 */
	public UserInfo.Address.Formatted getFormatted() {
	
		return formatted;
	}
	
	
	/**
	 * Sets the full mailing address, formatted for display or use with a
	 * mailing label. May contain newlines. Corresponds to the
	 * {@code formatted} claim.
	 *
	 * @param formatted The full mailing address, {@code null} if not 
	 *                  specified.
	 */
	public void setFormatted(final UserInfo.Address.Formatted formatted) {
	
		this.formatted = formatted;
	}
	
	
	/**
	 * Gets the full street address component, which may include house 
	 * number, street name, PO BOX, and multi-line extended street address 
	 * information. May contain newlines. Corresponds to the 
	 * {@code street_address} claim.
	 *
	 * @return The full street address component, {@code null} if not
	 *         specified.
	 */
	public UserInfo.Address.StreetAddress getStreetAddress() {
	
		return streetAddress;
	}
	
	
	/**
	 * Sets the full street address component, which may include house 
	 * number, street name, PO BOX, and multi-line extended street address 
	 * information. May contain newlines. Corresponds to the 
	 * {@code street_address} claim.
	 *
	 * @param streetAddress The full street address component, {@code null} 
	 *                      if not specified.
	 */
	public void setStreetAddress(final UserInfo.Address.StreetAddress streetAddress) {
	
		this.streetAddress = streetAddress;
	}
	
	
	/**
	 * Gets the city or locality component. Corresponds to the 
	 * {@code locality} claim.
	 *
	 * @return The city or locality component, {@code null} if not
	 *         specified.
	 */
	public UserInfo.Address.Locality getLocality() {
	
		return locality;
	}
	
	
	/**
	 * Sets the city or locality component. Corresponds to the 
	 * {@code locality} claim.
	 *
	 * @param locality The city or locality component, {@code null} if not
	 *                 specified.
	 */
	public void setLocality(final UserInfo.Address.Locality locality) {
	
		this.locality = locality;
	}
	
	
	/**
	 * Gets the state, province, prefecture or region component. Corresponds
	 * to the {@code region} claim.
	 *
	 * @return The state, province, prefecture or region component;
	 *         {@code null} if not specified.
	 */
	public UserInfo.Address.Region getRegion() {
	
		return region;
	}
	
	
	/**
	 * Sets the state, province, prefecture or region component. Corresponds
	 * to the {@code region} claim.
	 *
	 * @param region The state, province, prefecture or region component;
	 *               {@code null} if not specified.
	 */
	public void setRegion(final UserInfo.Address.Region region) {
	
		this.region = region;
	}
	
	
	/**
	 * Gets the zip code or postal code component. Corresponds to the
	 * {@code postal_code} claim.
	 *
	 * @return The zip code or postal code component, {@code null} if not
	 *         specified.
	 */
	public UserInfo.Address.PostalCode getPostalCode() {
	
		return postalCode;
	}
	
	
	/**
	 * Sets the zip code or postal code component. Corresponds to the
	 * {@code postal_code} claim.
	 *
	 * @param postalCode The zip code or postal code component, {@code null}
	 *                   if not specified.
	 */
	public void setPostalCode(final UserInfo.Address.PostalCode postalCode) {
	
		this.postalCode = postalCode;
	}
	
	
	/**
	 * Gets the country name component. Corresponds to the {@code country}
	 * claim.
	 *
	 * @return The country name component, {@code null} if not specified.
	 */
	public UserInfo.Address.Country getCountry() {
	
		return country;
	}
	
	
	/**
	 * Sets the country name component. Corresponds to the {@code country}
	 * claim.
	 *
	 * @param country The country name component, {@code null} if not 
	 *                specified.
	 */
	public void setCountry(final UserInfo.Address.Country country) {
	
		this.country = country;
	}
	
	
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
		
		if (formatted != null)
			o.put("formatted", formatted.getClaimValue());
			
		if (streetAddress != null)
			o.put("street_address", streetAddress.getClaimValue());
		
		if (locality != null)
			o.put("locality", locality.getClaimValue());
		
		if (region != null)
			o.put("region", region.getClaimValue());
		
		if (postalCode != null)
			o.put("postal_code", postalCode.getClaimValue());
		
		if (country != null)
			o.put("country", country.getClaimValue());
		
		return o;
	}
}
