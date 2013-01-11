package com.nimbusds.openid.connect.sdk.claims.sets;


import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.ParseException;

import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.Audience;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AuthenticationTime;
import com.nimbusds.openid.connect.sdk.claims.Claim;
import com.nimbusds.openid.connect.sdk.claims.ClaimValueParser;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.ExpirationTime;
import com.nimbusds.openid.connect.sdk.claims.GenericClaim;
import com.nimbusds.openid.connect.sdk.claims.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IssueTime;
import com.nimbusds.openid.connect.sdk.claims.NotBeforeTime;
import com.nimbusds.openid.connect.sdk.claims.Subject;

import com.nimbusds.openid.connect.sdk.messages.Nonce;

import com.nimbusds.openid.connect.sdk.util.JSONObjectUtils;


/**
 * ID Token claims, serialisable to a JSON object.
 *
 * <p>Example ID Token claims set:
 *
 * <pre>
 * {
 *   "iss"   : "http://server.example.com",
 *   "sub"   : "248289761001",
 *   "aud"   : "s6BhdRkqt3",
 *   "nonce" : "n-0S6_WzA2Mj",
 *   "exp"   : 1311281970,
 *   "iat"   : 1311280970
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-11)
 */
public class IDTokenClaims extends JSONObjectClaims {

	
	/**
	 * The names of the reserved ID Token claims.
	 */
	private static final Set<String> reservedClaimNames = new LinkedHashSet<String>();
	
	
	static {
		reservedClaimNames.add("iss");
		reservedClaimNames.add("sub");
		reservedClaimNames.add("aud");
		reservedClaimNames.add("exp");
		reservedClaimNames.add("iat");
		reservedClaimNames.add("acr");
		reservedClaimNames.add("nonce");
		reservedClaimNames.add("auth_time");
		reservedClaimNames.add("at_hash");
		reservedClaimNames.add("c_hash");
	}
	

	/**
	 * Gets the names of the reserved ID Token claims.
	 *
	 * @return The names of the reserved ID Token claims (read-only set).
	 */
	public static Set<String> getReservedClaimNames() {
	
		return Collections.unmodifiableSet(reservedClaimNames);
	}
	

	/**
	 * The issuer (required).
	 */
	private Issuer iss;
	
	
	/**
	 * The subject (required).
	 */
	private Subject sub;
	
	
	/**
	 * The audience that this token is intended for (required).
	 */
	private Audience aud;
	
	
	/**
	 * The expiration time on or after which the ID Token must not be 
	 * accepted for processing (required). The value is number of seconds 
	 * from 1970-01-01T0:0:0Z as measured in UTC until the desired 
	 * date/time.
	 */
	private ExpirationTime exp;
	
	
	/**
	 * The time at which this token was issued (required). The value is 
	 * number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the 
	 * desired date/time.
	 */
	private IssueTime iat;
	
	
	/**
	 * The Authentication Context Class Reference (optional).
	 */
	private ACR acr = null;
	
	
	/**
	 * Copy of the nonce parameter from the {@code AuthorizationRequest}
	 * (required).
	 */
	private Nonce nonce;
	
	
	/**
	 * The number of seconds from 1970-01-01T0:0:0Z as measured in UTC until 
	 * the date/time that the end-user authentication occurred (optional).
	 */
	private AuthenticationTime authTime = null;
	
	
	/**
	 * The access token hash, if an access token is issued in an implicit 
	 * flow.
	 */
	private AccessTokenHash atHash = null;
	
	
	/**
	 * The code hash, if a code is issued in an implicit flow.
	 */
	private CodeHash cHash = null;
	
	
	/**
	 * Creates a new minimal ID token. Use the setter methods for the 
	 * optional claims.
	 *
	 * @param iss   The issuer. Must not be {@code null}.
	 * @param sub   The subject. Must not be {@code null}.
	 * @param aud   The audience. Must not be {@code null}.
	 * @param iat   The issue time. Must not be {@code null}.
	 * @param nonce The nonce. If not required {@code null}.
	 */
	public IDTokenClaims(final Issuer iss, 
	                     final Subject sub, 
		             final Audience aud,
	                     final IssueTime iat, 
		             final Nonce nonce) {

		setIssuer(iss);
		setSubject(sub);
		setAudience(aud);
		setIssueTime(iat);
		setNonce(nonce);
	}
	
	
	/**
	 * Gets the issuer. Corresponds to the {@code iss} claim.
	 *
	 * @return The issuer identifier.
	 */
	public Issuer getIssuer() {
	
		return iss;
	}
	
	
	/**
	 * Sets the issuer. Corresponds to the {@code iss} claim.
	 *
	 * @param iss The issuer. Must not be {@code null}.
	 */
	public void setIssuer(final Issuer iss) {
	
		if (iss == null)
			throw new IllegalArgumentException("The issuer must not be null");
		
		this.iss = iss;
	}
	
	
	/**
	 * Gets the subject. Corresponds to the {@code sub} claim.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {
	
		return sub;
	}
	
	
	/**
	 * Sets the subject. Corresponds to the {@code sub} claim.
	 *
	 * @param sub The subject. Must not be {@code null}.
	 */
	public void setSubject(final Subject sub) {
	
		if (sub == null)
			throw new IllegalArgumentException("The subject must not be null");
			
		this.sub = sub;
	}
	
	
	/**
	 * Gets the audience. Corresponds to the {@code aud} claim.
	 *
	 * @return The audience.
	 */
	public Audience getAudience() {
	
		return aud;
	}
	
	
	/**
	 * Sets the audience. Corresponds to the {@code aud} claim.
	 *
	 * @param aud The audience. Must not be {@code null}.
	 */
	public void setAudience(final Audience aud) {
	
		if (aud == null)
			throw new IllegalArgumentException("The audience must not be null");
			
		this.aud = aud;
	}
	
	
	/**
	 * Gets the issue time. Corresponds to the {@code iat} claim.
	 *
	 * @return The issued-at time, as the number of seconds from 
	 *         1970-01-01T0:0:0Z as measured in UTC until the desired 
	 *         date/time.
	 */
	public IssueTime getIssueTime() {
	
		return iat;
	}
	
	
	/**
	 * Sets the issue time. Corresponds to the {@code iat} claim.
	 *
	 * @param iat The issued-at time, as the number of seconds from 
	 *            1970-01-01T0:0:0Z as measured in UTC until the desired 
	 *            date/time. Must not be {@code null}.
	 */
	public void setIssueTime(final IssueTime iat) {
	
		if (iat == null)
			throw new IllegalArgumentException("The issue time must not be null");
		
		this.iat = iat;
	}
	
	
	/**
	 * Gets the Authentication Context Class Reference. Corresponds to the
	 * optional {@code acr} claim.
	 *
	 * @return The Authentication Context Class Reference, {@code null} if
	 *         not specified.
	 */
	public ACR getACR() {
	
		return acr;
	}
	
	
	/**
	 * Sets the Authentication Context Class Reference. Corresponds to the
	 * optional {@code acr} claim.
	 *
	 * @param acr The Authentication Context Class Reference, {@code null}
	 *            if not specified.
	 */
	public void setACR(final ACR acr) {
	
		this.acr = acr;
	}
	
	
	/**
	 * Gets the nonce. Corresponds to the {@code nonce} claim.
	 *
	 * @return The nonce. If not required {@code null}.
	 */
	public Nonce getNonce() {
	
		return nonce;
	}
	
	
	/**
	 * Sets the nonce. Corresponds to the {@code nonce} claim.
	 *
	 * @param nonce The nonce. If not required {@code null}.
	 */
	public void setNonce(final Nonce nonce) {
	
		this.nonce = nonce;
	}
	
	
	/**
	 * Gets the authentication time. Corresponds to the optional 
	 * {@code auth_time} claim.
	 *
	 * @return The authentication time, as the number of seconds from 
	 *         1970-01-01T0:0:0Z as measured in UTC until the desired 
	 *         date/time. {@code null} if not specified.
	 */
	public AuthenticationTime getAuthenticationTime() {
	
		return authTime;
	}
	
	
	/**
	 * Sets the authentication time. Corresponds to the optional 
	 * {@code auth_time} claim.
	 *
	 * @param authTime The authentication time, as the number of seconds 
	 *                 from 1970-01-01T0:0:0Z as measured in UTC until the 
	 *                 desired date/time. {@code null} if not specified.
	 */
	public void setAuthenticationTime(final AuthenticationTime authTime) {
	
		this.authTime = authTime;
	}
	
	
	/**
	 * Gets the access token hash. Corresponds to the conditionally required
	 * {@code at_hash} claim.
	 *
	 * @return The access token hash. {@code null} if not specified.
	 */
	public AccessTokenHash getAccessTokenHash() {
	
		return atHash;
	}
	
	
	/**
	 * Sets the access token hash. Corresponds to the conditionally required
	 * {@code at_hash} claim.
	 *
	 * @param atHash The access token hash. {@code null} if not specified.
	 */
	public void setAccessTokenHash(final AccessTokenHash atHash) {
	
		this.atHash = atHash;
	}
	
	
	/**
	 * Gets the code hash. Corresponds to the conditionally required
	 * {@code c_hash} claim.
	 *
	 * @return The code hash. {@code null} if not specified.
	 */
	public CodeHash getCodeHash() {
	
		return cHash;
	}
	
	
	/**
	 * Sets the code hash. Corresponds to the conditionally required
	 * {@code c_hash} claim.
	 *
	 * @param cHash The code hash. {@code null} if not specified.
	 */
	public void setCodeHash(final CodeHash cHash) {
	
		this.cHash = cHash;
	}
	
	
	/**
	 * Gets a custom (non-reserved) claim from this ID Token claims set.
	 *
	 * @param claimName The name of the custom (non-reserved) claim.
	 *                  Must not be {@code null}.
	 *
	 * @return The matching custom claim, {@code null} if it doesn't exist
	 *         in this ID Token claims set.
	 */
	public Claim getCustomClaim(final String claimName) {
	
		return customClaims.get(claimName);
	}
	
	
	@Override
	public void addCustomClaim(final GenericClaim customClaim) {
	
		if (reservedClaimNames.contains(customClaim.getClaimName()))
			throw new IllegalArgumentException("Custom claim name conflicts with reserved claim name: " + customClaim.getClaimName());
	
		customClaims.put(customClaim.getClaimName(), customClaim);
	}
	
	
	@Override
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
		
		o.put("iss", iss.getClaimValue());
		o.put("sub", sub.getClaimValue());
		o.put("aud", aud.getClaimValue());
		o.put("exp", exp.getClaimValue());
		o.put("iat", iat.getClaimValue());
		
		if (acr != null)
			o.put("acr", acr.toString());
		
		o.put("nonce", nonce.toString());
		
		if (authTime != null)
			o.put("auth_time", authTime.getClaimValue());
		
		if (atHash != null)
			o.put("at_hash", atHash.getClaimValue());
		
		if (cHash != null)
			o.put("c_hash", cHash.getClaimValue());
		
		return o;
	}
	
	
	/**
	 * Parses an ID Token claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The ID Token claims set.
	 *
	 * @throws ParseException If the JSON object cannot be parsed to a valid
	 *                        ID Token claims set.
	 */
	public static IDTokenClaims parse(final JSONObject jsonObject)
		throws ParseException {
		
		// Get required ID token claims
		
		Issuer iss = new Issuer();
		ClaimValueParser.parse(jsonObject, iss);
		jsonObject.remove(iss.getClaimName());
		
		Subject sub = new Subject();
		ClaimValueParser.parse(jsonObject, sub);
		jsonObject.remove(sub.getClaimName());
		
		Audience aud = new Audience();
		ClaimValueParser.parse(jsonObject, aud);
		jsonObject.remove(aud.getClaimName());
		
		IssueTime iat = new IssueTime();
		ClaimValueParser.parse(jsonObject, iat);
		jsonObject.remove(iat.getClaimName());
		
		Nonce nonce = new Nonce(JSONObjectUtils.getString(jsonObject, "nonce"));
		
		IDTokenClaims idTokenClaims = new IDTokenClaims(iss, sub, aud, iat, nonce);
		
		
		// Get optional ID token claims
		
		ACR acr = new ACR();
		
		if (jsonObject.containsKey(acr.getClaimName())) {
			
			ClaimValueParser.parse(jsonObject, acr);
			jsonObject.remove(acr.getClaimName());
			idTokenClaims.setACR(acr);
		}
		
		
		AuthenticationTime authTime = new AuthenticationTime();
		
		if (jsonObject.containsKey(authTime.getClaimName())) {
		
			ClaimValueParser.parse(jsonObject, authTime);
			jsonObject.remove(authTime.getClaimName());
			idTokenClaims.setAuthenticationTime(authTime);
		}
		
		
		AccessTokenHash atHash = new AccessTokenHash();
		
		if (jsonObject.containsKey(atHash.getClaimName())) {
		
			ClaimValueParser.parse(jsonObject, atHash);
			jsonObject.remove(atHash.getClaimName());
			idTokenClaims.setAccessTokenHash(atHash);
		}
		
		
		CodeHash cHash = new CodeHash();
		
		if (jsonObject.containsKey(cHash.getClaimName())) {
		
			ClaimValueParser.parse(jsonObject, cHash);
			jsonObject.remove(cHash.getClaimName());
			idTokenClaims.setCodeHash(cHash);
		}
		
		
		// Add remaing claims as custom
		for (Map.Entry <String,Object> entry: jsonObject.entrySet()) {
			
			GenericClaim gc = new GenericClaim(entry.getKey());
			gc.setClaimValue(entry.getValue());
			
			idTokenClaims.addCustomClaim(gc);
		}
		
		return idTokenClaims;
	}
}
