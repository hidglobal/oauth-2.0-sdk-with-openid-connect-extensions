package com.nimbusds.openid.connect.claims.sets;


import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.claims.Claim;
import com.nimbusds.openid.connect.claims.ClaimName;
import com.nimbusds.openid.connect.claims.ClaimWithLangTag;
import com.nimbusds.openid.connect.claims.GenericClaim;
import com.nimbusds.openid.connect.claims.UserInfo;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * UserInfo address claims, serialisable to a JSON object.
 *
 * <p>Note: Supports language tags only at the top level. Tagged address members
 * are treated as {@link com.nimbusds.openid.connect.claims.GenericClaim 
 * generic claim}s.
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
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.4.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-23)
 */
public class AddressClaims extends JSONObjectClaims implements ClaimWithLangTag<JSONObject> {


	/**
	 * The names of the reserved UserInfo address claims.
	 */
	private static final Set<String> reservedClaimNames = new LinkedHashSet<String>();
	
	
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
	 * The language tag applied to the whole UserInfo address claims set.
	 */
	private LangTag langTag = null;
	
	
	/**
	 * The full mailing address, formatted for display or use with a mailing
	 * label (optional).
	 */
	private Map<LangTag, UserInfo.Address.Formatted> formattedEntries = null;
	
	
	/**
	 * The full street address component, which may include house number, 
	 * street name, PO BOX, and multi-line extended street address 
	 * information (optional).
	 */
	private Map<LangTag, UserInfo.Address.StreetAddress> streetAddressEntries = null;
	
	
	/**
	 * The city or locality component (optional).
	 */
	private Map<LangTag, UserInfo.Address.Locality> localityEntries = null;
	
	
	/**
	 * The state, province, prefecture or region component (optional).
	 */
	private Map<LangTag, UserInfo.Address.Region> regionEntries = null;
	
	
	/**
	 * The zip code or postal code component (optional).
	 */
	private Map<LangTag, UserInfo.Address.PostalCode> postalCodeEntries = null;
	
	
	/**
	 * The country name component (optional).
	 */
	private Map<LangTag, UserInfo.Address.Country> countryEntries = null;
	
	
	/**
	 * Creates a new minimal (empty) UserInfo address claims set. Use the 
	 * setter methods for the optional claims (all).
	 */
	public AddressClaims() {
	
		this(null);
	}
	
	
	/**
	 * Creates a new minimal (empty) UserInfo address claims set. Use the 
	 * setter methods for the optional claims (all).
	 *
	 * @param langTag The language tag to apply to the whole UserInfo claims
	 *                set, {@code null} if none.
	 */
	public AddressClaims(final LangTag langTag) {
	
		this.langTag = langTag;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Claim.ValueType getClaimValueType() {
	
		return Claim.ValueType.OBJECT;
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @return "address".
	 */
	public String getBaseClaimName() {
	
		return "address";
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @return "address" or "address#lang-tag".
	 */
	public String getClaimName() {
	
		if (langTag == null)
			return getBaseClaimName();
		
		else
			return getBaseClaimName() + '#' + langTag;
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @see #toJSONObject
	 *
	 * @return The JSON object representation of this UserInfo address 
	 *         claims set.
	 */
	public JSONObject getClaimValue() {
	
		return toJSONObject();
	}
	
	
	/**
	 * @inheritDoc
	 */
	public void setClaimValue(final JSONObject o) {
	
		AddressClaims ac = null;
		
		try {
			ac = AddressClaims.parse(o);
			
		} catch (ParseException e) {
		
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		
		// Copy all fields except LangTag
		this.formattedEntries = ac.formattedEntries;
		this.streetAddressEntries = ac.streetAddressEntries;
		this.localityEntries = ac.localityEntries;
		this.regionEntries = ac.regionEntries;
		this.postalCodeEntries = ac.postalCodeEntries;
		this.countryEntries = ac.countryEntries;
		this.customClaims = ac.customClaims;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public LangTag getLangTag() {
	
		return langTag;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public void setLangTag(final LangTag langTag) {
	
		this.langTag = langTag;
	}
	
	
	/**
	 * Adds the specified full mailing address, formatted for display or use
	 * with a mailing label. May contain newlines. Corresponds to the
	 * {@code formatted} claim.
	 *
	 * @param formatted The full mailing address, with optional language 
	 *                  tag. {@code null} if not specified.
	 */
	public void addFormatted(final UserInfo.Address.Formatted formatted) {
	
		if (formatted == null)
			return;
			
		if (formattedEntries == null)
			formattedEntries = new HashMap<LangTag,UserInfo.Address.Formatted>();
		
		formattedEntries.put(formatted.getLangTag(), formatted);
	}
	
	
	/**
	 * Gets the full mailing address, formatted for display or use with a
	 * mailing label. May contain newlines. Corresponds to the 
	 * {@code formatted} claim, with no language tag.
	 *
	 * @return The full mailing address with no language tag, {@code null} 
	 *         if not specified.
	 */
	public UserInfo.Address.Formatted getFormatted() {
	
		return getFormatted(null);
	}
	
	
	/**
	 * Gets the full mailing address, formatted for display or use with a
	 * mailing label. May contain newlines. Corresponds to the 
	 * {@code formatted} claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get the
	 *                untagged entry.
	 *
	 * @return The full mailing address, {@code null} if not specified.
	 */
	public UserInfo.Address.Formatted getFormatted(final LangTag langTag) {
	
		if (formattedEntries == null)
			return null;
		
		return formattedEntries.get(langTag);
	}
	
	
	/**
	 * Gets the full mailing address entries. Correspond to the 
	 * {@code formatted} claim.
	 *
	 * @return The full mailing address entries, {@code null} or empty map 
	 * if none.
	 */
	public Map<LangTag,UserInfo.Address.Formatted> getFormattedEntries() {
	
		return formattedEntries;
	}
	
	
	/**
	 * Adds the specified full street address component, which may include 
	 * house number, street name, PO BOX, and multi-line extended street 
	 * address information. May contain newlines. Corresponds to the 
	 * {@code street_address} claim.
	 *
	 * @param streetAddress The full street address component, with optional
	 *                      language tag. {@code null} if not specified.
	 */
	public void addStreetAddress(final UserInfo.Address.StreetAddress streetAddress) {
	
		if (streetAddress == null)
			return;
			
		if (streetAddressEntries == null)
			streetAddressEntries = new HashMap<LangTag,UserInfo.Address.StreetAddress>();
		
		streetAddressEntries.put(streetAddress.getLangTag(), streetAddress);
	}
	
	
	/**
	 * Gets the full street address component, which may include house 
	 * number, street name, PO BOX, and multi-line extended street address 
	 * information. May contain newlines. Corresponds to the 
	 * {@code street_address} claim, with no language tag.
	 *
	 * @return The full street address component with no language tag, 
	 *         {@code null} if not specified.
	 */
	public UserInfo.Address.StreetAddress getStreetAddress() {
	
		return getStreetAddress(null);
	}
	
	
	/**
	 * Gets the full street address component, which may include house 
	 * number, street name, PO BOX, and multi-line extended street address 
	 * information. May contain newlines. Corresponds to the 
	 * {@code street_address} claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get the
	 *                untagged entry.
	 *
	 * @return The full street address component, {@code null} if not 
	 *         specified.
	 */
	public UserInfo.Address.StreetAddress getStreetAddress(final LangTag langTag) {
	
		if (streetAddressEntries == null)
			return null;
		
		return streetAddressEntries.get(langTag);
	}
	
	
	/**
	 * Gets the full street address component entries. Correspond to the 
	 * {@code street_address} claim.
	 *
	 * @return The full street address component entries, {@code null} or 
	 *         empty map if none.
	 */
	public Map<LangTag,UserInfo.Address.StreetAddress> getStreetAddressEntries() {
	
		return streetAddressEntries;
	}
	
	
	/**
	 * Adds the specified city or locality component. Corresponds to the 
	 * {@code locality} claim.
	 *
	 * @param locality The city or locality component, with optional 
	 *                 language tag. {@code null} if not specified.
	 */
	public void addLocality(final UserInfo.Address.Locality locality) {
	
		if (locality == null)
			return;
		
		if (localityEntries == null)
			localityEntries = new HashMap<LangTag,UserInfo.Address.Locality>();
		
		localityEntries.put(locality.getLangTag(), locality);
	}
	
	
	/**
	 * Gets the city or locality component. Corresponds to the 
	 * {@code locality} claim, with no language tag.
	 *
	 * @return The city or locality component, {@code null} if not 
	 *         specified.
	 */
	public UserInfo.Address.Locality getLocality() {
	
		return getLocality(null);
	}
	
	
	/**
	 * Gets the city or locality component. Corresponds to the 
	 * {@code locality} claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get the
	 *                untagged entry.
	 *
	 * @return The city or locality component, {@code null} if not 
	 *         specified.
	 */
	public UserInfo.Address.Locality getLocality(final LangTag langTag) {
	
		if (localityEntries == null)
			return null;
		
		return localityEntries.get(langTag);
	}
	
	
	/**
	 * Gets the city or locality component entries. Correspond to the 
	 * {@code locality} claim.
	 *
	 * @return The city or locality component entries, {@code null} or empty
	 *         map if none.
	 */
	public Map<LangTag,UserInfo.Address.Locality> getLocalityEntries() {
	
		return localityEntries;
	}
	
	
	/**
	 * Adds the specified state, province, prefecture or region component.
	 * Corresponds to the {@code region} claim.
	 *
	 * @param region The state, province, prefecture or region component,
	 *               with optional language tag. {@code null} if not 
	 *               specified.
	 */
	public void addRegion(final UserInfo.Address.Region region) {
	
		if (region == null)
			return;
			
		if (regionEntries == null)
			regionEntries = new HashMap<LangTag,UserInfo.Address.Region>();
		
		regionEntries.put(region.getLangTag(), region);
	}
	
	
	/**
	 * Gets the state, province, prefecture or region component. Corresponds
	 * to the {@code region} claim, with no language tag.
	 *
	 * @return The state, province, prefecture or region component with no
	 *         language tag, {@code null} if not specified.
	 */
	public UserInfo.Address.Region getRegion() {
	
		return getRegion(null);
	}
	
	
	/**
	 * Gets the state, province, prefecture or region component. Corresponds
	 * to the {@code region} claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get the
	 *                untagged entry.
	 *
	 * @return The state, province, prefecture or region component,
	 *         {@code null} if not specified.
	 */
	public UserInfo.Address.Region getRegion(final LangTag langTag) {
	
		if (regionEntries == null)
			return null;
		
		return regionEntries.get(langTag);
	}
	
	
	/**
	 * Gets the state, province, prefecture or region component entries. 
	 * Correspond to the {@code region} claim.
	 *
	 * @return The state, province, prefecture or region component entries,
	 *         {@code null} or empty map if none.
	 */
	public Map<LangTag,UserInfo.Address.Region> getRegionEntries() {
	
		return regionEntries;
	}
	
	
	/**
	 * Adds the specified zip code or postal code component. Corresponds to 
	 * the {@code postal_code} claim.
	 *
	 * @param postalCode The zip code or postal code component, with 
	 *                   optional language tag. {@code null} if not 
	 *                   specified.
	 */
	public void addPostalCode(final UserInfo.Address.PostalCode postalCode) {
	
		if (postalCode == null)
			return;
		
		if (postalCodeEntries == null)
			postalCodeEntries = new HashMap<LangTag,UserInfo.Address.PostalCode>();
		
		postalCodeEntries.put(postalCode.getLangTag(), postalCode);
	}
	
	
	/**
	 * Gets the zip code or postal code component. Corresponds to the
	 * {@code postal_code} claim, with no language tag.
	 *
	 * @return The zip code or postal code component, {@code null} if not 
	 *         specified.
	 */
	public UserInfo.Address.PostalCode getPostalCode() {
	
		return getPostalCode(null);
	}
	
	
	/**
	 * Gets the zip code or postal code component. Corresponds to the
	 * {@code postal_code} claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get the
	 *                untagged entry.
	 *
	 * @return The zip code or postal code component, {@code null} if not 
	 *         specified.
	 */
	public UserInfo.Address.PostalCode getPostalCode(final LangTag langTag) {
	
		if (postalCodeEntries == null)
			return null;
		
		return postalCodeEntries.get(langTag);
	}
	
	
	/**
	 * Gets the zip code or postal code component entries. Correspond to the
	 * {@code postal_code} claim.
	 *
	 * @return The zip code or postal code component entries, {@code null} 
	 *         or empty map if none.
	 */
	public Map<LangTag,UserInfo.Address.PostalCode> getPostalCodeEntries() {
	
		return postalCodeEntries;
	}
	
	
	/**
	 * Adds the specified country name component. Corresponds to the 
	 * {@code country} claim.
	 *
	 * @param country The country name component, with optional language 
	 *                tag. {@code null} if not specified.
	 */
	public void addCountry(final UserInfo.Address.Country country) {
	
		if (country == null)
			return;
		
		if (countryEntries == null)
			countryEntries = new HashMap<LangTag,UserInfo.Address.Country>();
		
		countryEntries.put(country.getLangTag(), country);
	}
	
	
	/**
	 * Gets the country name component. Corresponds to the {@code country}
	 * claim, with no language tag.
	 *
	 * @return The country name component with no language tag, {@code null}
	 *         if not specified.
	 */
	public UserInfo.Address.Country getCountry() {
	
		return getCountry(null);
	}
	
	
	/**
	 * Gets the country name component. Corresponds to the {@code country}
	 * claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get the
	 *                untagged entry.
	 *
	 * @return The country name component, {@code null} if not specified.
	 */
	public UserInfo.Address.Country getCountry(final LangTag langTag) {
	
		if (countryEntries == null)
			return null;
		
		return countryEntries.get(langTag);
	}
	
	
	/**
	 * Gets the country name component entries. Correspond to the
	 * {@code country} claim.
	 *
	 * @return The country name component entries, {@code null} or empty map
	 *         if none.
	 */
	public Map<LangTag,UserInfo.Address.Country> getCountryEntries() {
	
		return countryEntries;
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
		
		JSONObjectClaims.putIntoJSONObject(o, formattedEntries);
		JSONObjectClaims.putIntoJSONObject(o, streetAddressEntries);
		JSONObjectClaims.putIntoJSONObject(o, localityEntries);
		JSONObjectClaims.putIntoJSONObject(o, regionEntries);
		JSONObjectClaims.putIntoJSONObject(o, postalCodeEntries);
		JSONObjectClaims.putIntoJSONObject(o, countryEntries);
		
		return o;
	}
	
	
	/**
	 * Parses a UserInfo address claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The UserInfo address claims set.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        valid UserInfo address claims set.
	 */
	public static AddressClaims parse(final JSONObject jsonObject)
		throws ParseException {
		
		AddressClaims ac = new AddressClaims();
		
		Iterator<String> it = jsonObject.keySet().iterator();
		
		while (it.hasNext()) {
		
			ClaimName claimName = ClaimName.parse(it.next());
			
			final String base = claimName.getBase();
			final LangTag langTag = claimName.getLangTag();
			
			
			if (base.equals("formatted")) {

				UserInfo.Address.Formatted formatted = new UserInfo.Address.Formatted();
				formatted.setClaimValue(JSONObjectUtils.getString(jsonObject, claimName.getName()));
				formatted.setLangTag(langTag);
				ac.addFormatted(formatted);
			}

			else if (base.equals("street_address")) {
				
				UserInfo.Address.StreetAddress streetAddress = new UserInfo.Address.StreetAddress();
				streetAddress.setClaimValue(JSONObjectUtils.getString(jsonObject, claimName.getName()));
				streetAddress.setLangTag(langTag);
				ac.addStreetAddress(streetAddress);
			}

			else if (base.equals("locality")) {
				
				UserInfo.Address.Locality locality = new UserInfo.Address.Locality();
				locality.setClaimValue(JSONObjectUtils.getString(jsonObject, claimName.getName()));
				locality.setLangTag(langTag);
				ac.addLocality(locality);
			}

			else if (base.equals("region")) {

				UserInfo.Address.Region region = new UserInfo.Address.Region();
				region.setClaimValue(JSONObjectUtils.getString(jsonObject, claimName.getName()));
				region.setLangTag(langTag);
				ac.addRegion(region);
			}

			else if (base.equals("postal_code")) {

				UserInfo.Address.PostalCode postalCode = new UserInfo.Address.PostalCode();
				postalCode.setClaimValue(JSONObjectUtils.getString(jsonObject, claimName.getName()));
				postalCode.setLangTag(langTag);
				ac.addPostalCode(postalCode);
			}

			else if (base.equals("country")) {

				UserInfo.Address.Country country = new UserInfo.Address.Country();
				country.setClaimValue(JSONObjectUtils.getString(jsonObject, claimName.getName()));
				country.setLangTag(langTag);
				ac.addCountry(country);
			}
		
			else {
				// Custom claim
				
				GenericClaim gc = new GenericClaim(claimName.getName());
				gc.setClaimValue(jsonObject.get(claimName.getName()));
				ac.addCustomClaim(gc);
			}
		}
		
		return ac;
	}
}
