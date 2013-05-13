package com.nimbusds.openid.connect.sdk.claims;


import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import net.minidev.json.JSONObject;


/**
 * UserInfo address claims set, serialisable to a JSON object.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.4.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-23)
 */
public class Address extends ClaimsSet {


	/**
	 * The names of the standard UserInfo address claims.
	 */
	private static final Set<String> stdClaimNames = new LinkedHashSet<String>();
	
	
	static {
		stdClaimNames.add("formatted");
		stdClaimNames.add("street_address");
		stdClaimNames.add("locality");
		stdClaimNames.add("region");
		stdClaimNames.add("postal_code");
		stdClaimNames.add("country");
	}
	
	
	/**
	 * Gets the names of the standard UserInfo address claims.
	 *
	 * @return The names of the standard UserInfo address claims 
	 *         (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
	
		return Collections.unmodifiableSet(stdClaimNames);
	}
	
	
	/**
	 * Creates a new minimal (empty) UserInfo address claims set.
	 */
	public Address() { }


	/**
	 * Creates a new UserInfo address claims set from the specified JSON 
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	public Address(final JSONObject jsonObject) {

		super(jsonObject);
	}
	
	
	/**
	 * Sets the full mailing address, formatted for display or use with a 
	 * mailing label. May contain newlines. Corresponds to the
	 * {@code formatted} claim.
	 *
	 * @param formatted The full mailing address. {@code null} if not 
	 *                  specified.
	 */
	public void setFormatted(final String formatted) {
	
		setClaim("formatted", formatted);
	}
	
	
	/**
	 * Gets the full mailing address, formatted for display or use with a
	 * mailing label. May contain newlines. Corresponds to the 
	 * {@code formatted} claim.
	 *
	 * @return The full mailing address, {@code null} if not specified.
	 */
	public String getFormatted() {
	
		return getStringClaim("formatted");
	}
	
	
	/**
	 * Sets the full street address component, which may include house
	 * number, street name, PO BOX, and multi-line extended street address
	 * information. May contain newlines. Corresponds to the 
	 * {@code street_address} claim.
	 *
	 * @param streetAddress The full street address component. {@code null}
	 *                      if not specified.
	 */
	public void setStreetAddress(final String streetAddress) {
	
		setClaim("street_address", streetAddress);
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
	public String getStreetAddress() {
	
		return getStringClaim("street_address");
	}
	
	
	/**
	 * Sets the city or locality component. Corresponds to the 
	 * {@code locality} claim.
	 *
	 * @param locality The city or locality component. {@code null} if not 
	 *                 specified.
	 */
	public void setLocality(final String locality) {
	
		setClaim("locality", locality);
	}
	
	
	/**
	 * Gets the city or locality component. Corresponds to the 
	 * {@code locality} claim, with no language tag.
	 *
	 * @return The city or locality component, {@code null} if not 
	 *         specified.
	 */
	public String getLocality() {
	
		return getStringClaim("locality");
	}
	
	
	/**
	 * Sets the state, province, prefecture or region component. 
	 * Corresponds to the {@code region} claim.
	 *
	 * @param region The state, province, prefecture or region component.
	 *               {@code null} if not specified.
	 */
	public void setRegion(final String region) {
	
		setClaim("region", region);
	}
	
	
	/**
	 * Gets the state, province, prefecture or region component. 
	 * Corresponds to the {@code region} claim.
	 *
	 * @return The state, province, prefecture or region component,
	 *         {@code null} if not specified.
	 */
	public String getRegion() {
	
		return getStringClaim("region");
	}
	
	
	/**
	 * Sets the zip code or postal code component. Corresponds to the
	 * {@code postal_code} claim.
	 *
	 * @param postalCode The zip code or postal code component.
	 *                   {@code null} if not specified.
	 */
	public void setPostalCode(final String postalCode) {
	
		setClaim("postal_code", postalCode);
	}
	
	
	/**
	 * Gets the zip code or postal code component. Corresponds to the
	 * {@code postal_code} claim.
	 *
	 * @return The zip code or postal code component, {@code null} if not 
	 *         specified.
	 */
	public String getPostalCode() {
	
		return getStringClaim("postal_code");
	}
	
	
	/**
	 * Sets the country name component. Corresponds to the {@code country} 
	 * claim.
	 *
	 * @param country The country name component. {@code null} if not 
	 *                specified.
	 */
	public void setCountry(final String country) {
	
		setClaim("country", country);
	}
	
	
	/**
	 * Gets the country name component. Corresponds to the {@code country}
	 * claim.
	 *
	 * @return The country name component, {@code null} if not specified.
	 */
	public String getCountry() {
	
		return getStringClaim("country");
	}
}
