package com.nimbusds.openid.connect.sdk.claims;


import java.util.*;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.Nonce;


/**
 * ID token claims set, serialisable to a JSON object.
 *
 * <p>Example ID token claims set:
 *
 * <pre>
 * {
 *   "iss"       : "https://server.example.com",
 *   "sub"       : "24400320",
 *   "aud"       : "s6BhdRkqt3",
 *   "nonce"     : "n-0S6_WzA2Mj",
 *   "exp"       : 1311281970,
 *   "iat"       : 1311280970,
 *   "auth_time" : 1311280969,
 *   "acr"       : "urn:mace:incommon:iap:silver",
 *   "at_hash"   : "MTIzNDU2Nzg5MDEyMzQ1Ng"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 2.
 * </ul>
 */
public class IDTokenClaimsSet extends ClaimsSet {


	/**
	 * The issuer claim name.
	 */
	public static final String ISS_CLAIM_NAME = "iss";


	/**
	 * The subject claim name.
	 */
	public static final String SUB_CLAIM_NAME = "sub";


	/**
	 * The audience claim name.
	 */
	public static final String AUD_CLAIM_NAME = "aud";


	/**
	 * The expiration time claim name.
	 */
	public static final String EXP_CLAIM_NAME = "exp";


	/**
	 * The issue time claim name.
	 */
	public static final String IAT_CLAIM_NAME = "iat";


	/**
	 * The subject authentication time claim name.
	 */
	public static final String AUTH_TIME_CLAIM_NAME = "auth_time";


	/**
	 * The nonce claim name.
	 */
	public static final String NONCE_CLAIM_NAME = "nonce";


	/**
	 * The access token hash claim name.
	 */
	public static final String AT_HASH_CLAIM_NAME = "at_hash";


	/**
	 * The authorisation code hash claim name.
	 */
	public static final String C_HASH_CLAIM_NAME = "c_hash";


	/**
	 * The ACR claim name.
	 */
	public static final String ACR_CLAIM_NAME = "acr";


	/**
	 * The AMRs claim name.
	 */
	public static final String AMR_CLAIM_NAME = "amr";


	/**
	 * The authorised party claim name.
	 */
	public static final String AZP_CLAIM_NAME = "azp";


	/**
	 * The subject JWK claim name.
	 */
	public static final String SUB_JWK_CLAIM_NAME = "sub_jwk";


	/**
	 * The names of the standard top-level ID token claims.
	 */
	private static final Set<String> stdClaimNames = new LinkedHashSet<>();


	static {
		stdClaimNames.add(ISS_CLAIM_NAME);
		stdClaimNames.add(SUB_CLAIM_NAME);
		stdClaimNames.add(AUD_CLAIM_NAME);
		stdClaimNames.add(EXP_CLAIM_NAME);
		stdClaimNames.add(IAT_CLAIM_NAME);
		stdClaimNames.add(AUTH_TIME_CLAIM_NAME);
		stdClaimNames.add(NONCE_CLAIM_NAME);
		stdClaimNames.add(AT_HASH_CLAIM_NAME);
		stdClaimNames.add(C_HASH_CLAIM_NAME);
		stdClaimNames.add(ACR_CLAIM_NAME);
		stdClaimNames.add(AMR_CLAIM_NAME);
		stdClaimNames.add(AZP_CLAIM_NAME);
		stdClaimNames.add(SUB_JWK_CLAIM_NAME);
	}


	/**
	 * Gets the names of the standard top-level ID token claims.
	 *
	 * @return The names of the standard top-level ID token claims
	 *         (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {

		return Collections.unmodifiableSet(stdClaimNames);
	}


	/**
	 * Creates a new minimal ID token claims set. Note that the ID token
	 * may require additional claims to be present depending on the
	 * original OpenID Connect authorisation request.
	 *
	 * @param iss The issuer. Must not be {@code null}.
	 * @param sub The subject. Must not be {@code null}.
	 * @param aud The audience. Must not be {@code null}.
	 * @param exp The expiration time. Must not be {@code null}.
	 * @param iat The issue time. Must not be {@code null}.
	 */
	public IDTokenClaimsSet(final Issuer iss,
				final Subject sub,
				final List<Audience> aud,
				final Date exp,
				final Date iat) {

		setClaim(ISS_CLAIM_NAME, iss.getValue());
		setClaim(SUB_CLAIM_NAME, sub.getValue());

		JSONArray audList = new JSONArray();

		for (Audience a: aud)
			audList.add(a.getValue());

		setClaim(AUD_CLAIM_NAME, audList);

		setDateClaim(EXP_CLAIM_NAME, exp);
		setDateClaim(IAT_CLAIM_NAME, iat);
	}


	/**
	 * Creates a new ID token claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must be verified to represent a
	 *                   valid ID token claims set and not {@code null}.
	 *
	 * @throws ParseException If the JSON object doesn't contain the
	 *                        minimally required issuer {@code iss},
	 *                        subject {@code sub}, audience list
	 *                        {@code aud}, expiration date {@code exp} and
	 *                        issue date {@code iat} claims.
	 */
	private IDTokenClaimsSet(final JSONObject jsonObject)
		throws ParseException {

		super(jsonObject);

		if (getStringClaim(ISS_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid \"iss\" claim");

		if (getStringClaim(SUB_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid \"sub\" claim");

		if (getStringClaim(AUD_CLAIM_NAME) == null && getStringListClaim(AUD_CLAIM_NAME) == null ||
		    getStringListClaim(AUD_CLAIM_NAME) != null && getStringListClaim(AUD_CLAIM_NAME).isEmpty())
			throw new ParseException("Missing or invalid \"aud\" claim");

		if (getDateClaim(EXP_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid \"exp\" claim");

		if (getDateClaim(IAT_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid \"iat\" claim");
	}


	/**
	 * Creates a new ID token claims set from the specified JSON Web Token
	 * (JWT) claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @throws ParseException If the JSON object doesn't contain the
	 *                        minimally required issuer {@code iss},
	 *                        subject {@code sub}, audience list
	 *                        {@code aud}, expiration date {@code exp} and
	 *                        issue date {@code iat} claims.
	 */
	public IDTokenClaimsSet(final ReadOnlyJWTClaimsSet jwtClaimsSet)
		throws ParseException {

		this(jwtClaimsSet.toJSONObject());
	}


	/**
	 * Checks if this ID token claims set contains all required claims for
	 * the specified OpenID Connect response type.
	 *
	 * @param rt The OpenID Connect response type. Must not be
	 *           {@code null}.
	 *
	 * @return {@code true} if the required claims are contained, else
	 *         {@code false}.
	 */
	public boolean hasRequiredClaims(final ResponseType rt) {

		if (rt.impliesImplicitFlow() && getNonce() == null)
			return false;

		if (rt.impliesImplicitFlow() && rt.contains(ResponseType.Value.TOKEN) && getAccessTokenHash() == null)
			return false;

		if (rt.impliesCodeFlow() && getCodeHash() == null)
			return false;

		return true;
	}


	/**
	 * Gets the ID token issuer. Corresponds to the {@code iss} claim.
	 *
	 * @return The issuer.
	 */
	public Issuer getIssuer() {

		return new Issuer(getStringClaim(ISS_CLAIM_NAME));
	}


	/**
	 * Gets the ID token subject. Corresponds to the {@code sub} claim.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {

		return new Subject(getStringClaim(SUB_CLAIM_NAME));
	}


	/**
	 * Gets the ID token audience. Corresponds to the {@code aud} claim.
	 *
	 * @return The audience.
	 */
	public List<Audience> getAudience() {

		if (getClaim(AUD_CLAIM_NAME) instanceof String) {
			// Special case - aud is a string
			return new Audience(getStringClaim(AUD_CLAIM_NAME)).toSingleAudienceList();
		}

		// General case - JSON string array
		List<String> rawList = getStringListClaim(AUD_CLAIM_NAME);

		List<Audience> audList = new ArrayList<>(rawList.size());

		for (String s: rawList)
			audList.add(new Audience(s));

		return audList;
	}


	/**
	 * Gets the ID token expiration time. Corresponds to the {@code exp}
	 * claim.
	 *
	 * @return The expiration time.
	 */
	public Date getExpirationTime() {

		return getDateClaim(EXP_CLAIM_NAME);
	}


	/**
	 * Gets the ID token issue time. Corresponds to the {@code iss} claim.
	 *
	 * @return The issue time.
	 */
	public Date getIssueTime() {

		return getDateClaim(IAT_CLAIM_NAME);
	}


	/**
	 * Gets the subject authentication time. Corresponds to the
	 * {@code auth_time} claim.
	 *
	 * @return The authentication time, {@code null} if not specified or
	 *         parsing failed.
	 */
	public Date getAuthenticationTime() {

		return getDateClaim(AUTH_TIME_CLAIM_NAME);
	}


	/**
	 * Sets the subject authentication time. Corresponds to the
	 * {@code auth_time} claim.
	 *
	 * @param authTime The authentication time, {@code null} if not
	 *                 specified.
	 */
	public void setAuthenticationTime(final Date authTime) {

		setDateClaim(AUTH_TIME_CLAIM_NAME, authTime);
	}


	/**
	 * Gets the ID token nonce. Corresponds to the {@code nonce} claim.
	 *
	 * @return The nonce, {@code null} if not specified or parsing failed.
	 */
	public Nonce getNonce() {

		String value = getStringClaim(NONCE_CLAIM_NAME);
		return value != null ? new Nonce(value) : null;
	}


	/**
	 * Sets the ID token nonce. Corresponds to the {@code nonce} claim.
	 *
	 * @param nonce The nonce, {@code null} if not specified.
	 */
	public void setNonce(final Nonce nonce) {

		if (nonce != null)
			setClaim(NONCE_CLAIM_NAME, nonce.getValue());
		else
			setClaim(NONCE_CLAIM_NAME, null);
	}


	/**
	 * Gets the access token hash. Corresponds to the {@code at_hash}
	 * claim.
	 *
	 * @return The access token hash, {@code null} if not specified or
	 *         parsing failed.
	 */
	public AccessTokenHash getAccessTokenHash() {

		String value = getStringClaim(AT_HASH_CLAIM_NAME);
		return value != null ? new AccessTokenHash(value) : null;
	}


	/**
	 * Sets the access token hash. Corresponds to the {@code at_hash}
	 * claim.
	 *
	 * @param atHash The access token hash, {@code null} if not specified.
	 */
	public void setAccessTokenHash(final AccessTokenHash atHash) {

		if (atHash != null)
			setClaim(AT_HASH_CLAIM_NAME, atHash.getValue());
		else
			setClaim(AT_HASH_CLAIM_NAME, null);
	}


	/**
	 * Gets the authorisation code hash. Corresponds to the {@code c_hash}
	 * claim.
	 *
	 * @return The authorisation code hash, {@code null} if not specified
	 *         or parsing failed.
	 */
	public CodeHash getCodeHash() {

		String value = getStringClaim(C_HASH_CLAIM_NAME);
		return value != null ? new CodeHash(value) : null;
	}


	/**
	 * Sets the authorisation code hash. Corresponds to the {@code c_hash}
	 * claim.
	 *
	 * @param cHash The authorisation code hash, {@code null} if not
	 *              specified.
	 */
	public void setCodeHash(final CodeHash cHash) {

		if (cHash != null)
			setClaim(C_HASH_CLAIM_NAME, cHash.getValue());
		else
			setClaim(C_HASH_CLAIM_NAME, null);
	}


	/**
	 * Gets the Authentication Context Class Reference (ACR). Corresponds
	 * to the {@code acr} claim.
	 *
	 * @return The Authentication Context Class Reference (ACR),
	 *         {@code null} if not specified or parsing failed.
	 */
	public ACR getACR() {

		String value = getStringClaim(ACR_CLAIM_NAME);
		return value != null ? new ACR(value) : null;
	}


	/**
	 * Sets the Authentication Context Class Reference (ACR). Corresponds
	 * to the {@code acr} claim.
	 *
	 * @param acr The Authentication Context Class Reference (ACR),
	 *            {@code null} if not specified.
	 */
	public void setACR(final ACR acr) {

		if (acr != null)
			setClaim(ACR_CLAIM_NAME, acr.getValue());
		else
			setClaim(ACR_CLAIM_NAME, null);
	}


	/**
	 * Gets the Authentication Methods References (AMRs). Corresponds to
	 * the {@code amr} claim.
	 *
	 * @return The Authentication Methods Reference (AMR) list,
	 *         {@code null} if not specified or parsing failed.
	 */
	public List<AMR> getAMR() {

		List<String> rawList = getStringListClaim(AMR_CLAIM_NAME);

		if (rawList == null || rawList.isEmpty())
			return null;

		List<AMR> amrList = new ArrayList<>(rawList.size());

		for (String s: rawList)
			amrList.add(new AMR(s));

		return amrList;
	}


	/**
	 * Sets the Authentication Methods References (AMRs). Corresponds to
	 * the {@code amr} claim.
	 *
	 * @param amr The Authentication Methods Reference (AMR) list,
	 *            {@code null} if not specified.
	 */
	public void setAMR(final List<AMR> amr) {

		if (amr != null) {

			List<String> amrList = new ArrayList<>(amr.size());

			for (AMR a: amr)
				amrList.add(a.getValue());

			setClaim(AMR_CLAIM_NAME, amrList);

		} else {
			setClaim(AMR_CLAIM_NAME, null);
		}
	}


	/**
	 * Gets the authorised party for the ID token. Corresponds to the
	 * {@code azp} claim.
	 *
	 * @return The authorised party, {@code null} if not specified or
	 *         parsing failed.
	 */
	public AuthorizedParty getAuthorizedParty() {

		String value = getStringClaim(AZP_CLAIM_NAME);
		return value != null ? new AuthorizedParty(value) : null;
	}


	/**
	 * Sets the authorised party for the ID token. Corresponds to the
	 * {@code azp} claim.
	 *
	 * @param azp The authorised party, {@code null} if not specified.
	 */
	public void setAuthorizedParty(final AuthorizedParty azp) {

		if (azp != null)
			setClaim(AZP_CLAIM_NAME, azp.getValue());
		else
			setClaim(AZP_CLAIM_NAME, null);
	}


	/**
	 * Gets the subject's JSON Web Key (JWK) for a self-issued OpenID
	 * Connect provider. Corresponds to the {@code sub_jwk} claim.
	 *
	 * @return The subject's JWK, {@code null} if not specified or parsing
	 *         failed.
	 */
	public JWK getSubjectJWK() {

		JSONObject jsonObject = getClaim(SUB_JWK_CLAIM_NAME, JSONObject.class);

		if (jsonObject == null)
			return null;

		try {
			return JWK.parse(jsonObject);

		} catch (java.text.ParseException e) {

			return null;
		}
	}


	/**
	 * Sets the subject's JSON Web Key (JWK) for a self-issued OpenID
	 * Connect provider. Corresponds to the {@code sub_jwk} claim.
	 *
	 * @param subJWK The subject's JWK (must be public), {@code null} if
	 *               not specified.
	 */
	public void setSubjectJWK(final JWK subJWK) {

		if (subJWK != null) {

			if (subJWK.isPrivate())
				throw new IllegalArgumentException("The subject's JSON Web Key (JWK) must be public");

			setClaim(SUB_JWK_CLAIM_NAME, subJWK.toJSONObject());

		} else {
			setClaim(SUB_JWK_CLAIM_NAME, null);
		}
	}


	/**
	 * Parses an ID token claims set from the specified JSON object string.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The ID token claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IDTokenClaimsSet parse(final String json)
		throws ParseException {

		JSONObject jsonObject = JSONObjectUtils.parseJSONObject(json);

		try {
			return new IDTokenClaimsSet(jsonObject);

		} catch (IllegalArgumentException e) {

			throw new ParseException(e.getMessage(), e);
		}
	}
}
