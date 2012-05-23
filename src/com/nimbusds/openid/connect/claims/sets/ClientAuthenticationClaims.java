package com.nimbusds.openid.connect.claims.sets;


import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.claims.Audience;
import com.nimbusds.openid.connect.claims.ClaimValueParser;
import com.nimbusds.openid.connect.claims.ExpirationTime;
import com.nimbusds.openid.connect.claims.GenericClaim;
import com.nimbusds.openid.connect.claims.Issuer;
import com.nimbusds.openid.connect.claims.IssueTime;
import com.nimbusds.openid.connect.claims.JWTID;
import com.nimbusds.openid.connect.claims.NotBeforeTime;
import com.nimbusds.openid.connect.claims.Principal;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * Client authentication claims, serialisable to a JSON object. Used for 
 * {@link com.nimbusds.openid.connect.messages.ClientSecretJWT client secret 
 * JWT} and {@link com.nimbusds.openid.connect.messages.PrivateKeyJWT private 
 * key JWT} authentication at the Token endpoint.
 *
 * <p>Note that OpenID Connect mandates the use the {@code jti} claim, see
 * https://bitbucket.org/openid/connect/issue/583/messages-221-client-auth-claims-not
 *
 * <p>Example client authentication claims set:
 *
 * <pre>
 * {
 *   "iss" : "http://client.example.com",
 *   "prn" : "http://client.example.com",
 *   "aud" : "http://server.example.com",
 *   "jti" : "d396036d-c4d9-40d8-8e98-f7e8327002d9",
 *   "exp" : 1311281970,
 *   "iat" : 1311280970
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.1.
 *     <li>draft-jones-oauth-jwt-bearer-04
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-23)
 */
public class ClientAuthenticationClaims extends JSONObjectClaims {


	/**
	 * The names of the reserved client authentication claims.
	 */
	private static final Set<String> reservedClaimNames = new LinkedHashSet<String>();
	
	
	static {
		reservedClaimNames.add("iss");
		reservedClaimNames.add("prn");
		reservedClaimNames.add("aud");
		reservedClaimNames.add("jti");
		reservedClaimNames.add("exp");
		reservedClaimNames.add("iat");
		reservedClaimNames.add("nbf");
	}
	

	/**
	 * Gets the names of the reserved client authentication claims.
	 *
	 * @return The names of the reserved client authentication claims 
	 *         (read-only set).
	 */
	public static Set<String> getReservedClaimNames() {
	
		return Collections.unmodifiableSet(reservedClaimNames);
	}
	
	
	/**
	 * The issuer (required).
	 */
	private Issuer iss;
	
	
	/**
	 * The principal (required).
	 */
	private Principal prn;
	
	
	/**
	 * The audience that this token is intended for (required).
	 */
	private Audience aud;
	
	
	/**
	 * The unique identifier for the JWT (required). The JWT ID may be used
	 * by implementations requiring message de-duplication for one-time use 
	 * assertions. 
	 */
	private JWTID jti = null;
	
	
	/**
	 * The expiration time that limits the time window during which the JWT 
	 * can be used (required). The value is number of seconds from 
	 * 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
	 */
	private ExpirationTime exp;
	
	
	/**
	 * The time at which this token was issued (optional). The value is 
	 * number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the 
	 * desired date/time.
	 */
	private IssueTime iat = null;
	
	
	/**
	 * The time before which this token must not be accepted for processing.
	 * The value is number of seconds from 1970-01-01T0:0:0Z as measured in 
	 * UTC until the desired date/time.
	 */
	private NotBeforeTime nbf = null;
	
	
	/**
	 * Creates a new minimal client authentication claims instance. Use the 
	 * setter methods for the optional claims.
	 *
	 * @param iss The issuer. Must contain the {@code client_id} of the
	 *            OAuth client. Must not be {@code null}.
	 * @param prn The principal. Must contain the {@code client_id} of the
	 *            OAuth client. Must not be {@code null}.
	 * @param aud The audience, typically the URL of the authorisation 
	 *            server's token endpoint. Must not be {@code null}.
	 * @param jti The unique identifier for the JWT. The JWT ID may be used
	 *            by implementations requiring message de-duplication for 
	 *            one-time use assertions.
	 * @param exp The expiration time. Must not be {@code null}.
	 */
	public ClientAuthenticationClaims(final Issuer iss, 
	                                  final Principal prn, 
					  final Audience aud,
					  final JWTID jti,
					  final ExpirationTime exp) {

		setIssuer(iss);
		setPrincipal(prn);
		setAudience(aud);
		setJWTID(jti);
		setExpirationTime(exp);
	}
	
	
	/**
	 * Gets the issuer. Corresponds to the {@code iss} claim.
	 *
	 * @return The issuer. Contains the {@code client_id} of the OAuth 
	 *         client.
	 */
	public Issuer getIssuer() {
	
		return iss;
	}
	
	
	/**
	 * Sets the issuer. Corresponds to the {@code iss} claim.
	 *
	 * @param iss The issuer. Must contain the {@code client_id} of the
	 *            OAuth client. Must not be {@code null}.
	 */
	public void setIssuer(final Issuer iss) {
	
		if (iss == null)
			throw new NullPointerException("The issuer must not be null");
		
		this.iss = iss;
	}
	
	
	/**
	 * Gets the principal. Corresponds to the {@code prn} claim.
	 *
	 * @return The principal. Contains the {@code client_id} of the OAuth 
	 *         client.
	 */
	public Principal getPrincipal() {
	
		return prn;
	}
	
	
	/**
	 * Sets the principal. Corresponds to the {@code prn} claim.
	 *
	 * @param prn The principal. Must contain the {@code client_id} of the
	 *            OAuth client. Must not be {@code null}.
	 */
	public void setPrincipal(final Principal prn) {
	
		if (prn == null)
			throw new NullPointerException("The principal must not be null");
		
		this.prn = prn;
	}
	
	
	/**
	 * Gets the audience. Corresponds to the {@code aud} claim.
	 *
	 * @return The audience, typically the URL of the authorisation 
	 *         server's token endpoint.
	 */
	public Audience getAudience() {
	
		return aud;
	}
	
	
	/**
	 * Sets the audience. Corresponds to the {@code aud} claim.
	 *
	 * @param aud The audience, typically the URL of the authorisation 
	 *            server's token endpoint. Must not be {@code null}.
	 */
	public void setAudience(final Audience aud) {
	
		if (aud == null)
			throw new NullPointerException("The audience must not be null");
			
		this.aud = aud;
	}
	
	
	/**
	 * Gets the identfier for the JWT. Corresponds to the {@code jti} claim.
	 *
	 * @return The identifier for the JWT.
	 */
	public JWTID getJWTID() {
	
		return jti;
	}
	
	
	/**
	 * Sets the identifier for the JWT. Corresponds to the {@code jti} claim.
	 *
	 * @param jti The identifier for the JWT. Must not be {@code null}.
	 */
	public void setJWTID(final JWTID jti) {
	
		if (jti == null)
			throw new NullPointerException("The JWT ID must not be null");
		
		this.jti = jti;
	}
	
	
	/**
	 * Gets the expiration time. Corresponds to the {@code exp} claim.
	 *
	 * @return The expiration time.
	 */
	public ExpirationTime getExpirationTime() {
	
		return exp;
	}
	
	
	/**
	 * Sets the expiration time. Corresponds to the {@code exp} claim.
	 *
	 * @param exp The expiration time. Must not be {@code null}.
	 */
	public void setExpirationTime(final ExpirationTime exp) {
	
		if (exp == null)
			throw new NullPointerException("The expiration time must not be null");
		
		this.exp = exp;
	}
	
	
	/**
	 * Gets the optional issue time. Corresponds to the {@code iat} claim.
	 *
	 * @return The issued-at time, as the number of seconds from 
	 *         1970-01-01T0:0:0Z as measured in UTC until the desired 
	 *         date/time. {@code null} if not specified.
	 */
	public IssueTime getIssueTime() {
	
		return iat;
	}
	
	
	/**
	 * Sets the optional issue time. Corresponds to the {@code iat} claim.
	 *
	 * @param iat The issued-at time, as the number of seconds from 
	 *            1970-01-01T0:0:0Z as measured in UTC until the desired 
	 *            date/time. {@code null} if not specified.
	 */
	public void setIssueTime(final IssueTime iat) {
	
		this.iat = iat;
	}
	
	
	/**
	 * Gets the not-before time. Corresponds to the {@code nbf} claim.
	 *
	 * @return The not-before time, as the number of seconds from 
	 *         1970-01-01T0:0:0Z as measured in UTC until the desired 
	 *         date/time. {@code null} if not specified.
	 */
	public NotBeforeTime getNotBeforeTime() {
	
		return nbf;
	}
	
	
	/**
	 * Sets the not-before time. Corresponds to the {@code nbf} claim.
	 *
	 * @param nbf The not-before time, as the number of seconds from 
	 *            1970-01-01T0:0:0Z as measured in UTC until the desired 
	 *            date/time. {@code null} if not specified.
	 */
	public void setNotBeforeTime(final NotBeforeTime nbf) {
	
		this.nbf = nbf;
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
	
		JSONObject o = super.toJSONObject();
		
		o.put("iss", iss.getClaimValue());
		o.put("prn", prn.getClaimValue());
		o.put("aud", aud.getClaimValue());
		o.put("jti", jti.getClaimValue());
		o.put("exp", exp.getClaimValue());
		
		if (iat != null)
			o.put("iat", iat.getClaimValue());
		
		if (nbf != null)
			o.put("nbf", nbf.getClaimValue());
		
		return o;
	}
	
	
	/**
	 * Parses a client authentication claims set from the specified JSON 
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The client authentication claims set.
	 *
	 * @throws ParseException If the JSON object cannot be parsed to a valid
	 *                        client authentication claims set.
	 */
	public static ClientAuthenticationClaims parse(final JSONObject jsonObject)
		throws ParseException {
		
		// Get required ID token claims
		
		Issuer iss = new Issuer();
		ClaimValueParser.parse(jsonObject, iss);
		jsonObject.remove(iss.getClaimName());
		
		Principal prn = new Principal();
		ClaimValueParser.parse(jsonObject, prn);
		jsonObject.remove(prn.getClaimName());
		
		Audience aud = new Audience();
		ClaimValueParser.parse(jsonObject, aud);
		jsonObject.remove(aud.getClaimName());
		
		ExpirationTime exp = new ExpirationTime();
		ClaimValueParser.parse(jsonObject, exp);
		jsonObject.remove(exp.getClaimName());
		
		JWTID jti = new JWTID();
		ClaimValueParser.parse(jsonObject, jti);
		jsonObject.remove(jti.getClaimName());
		
		
		ClientAuthenticationClaims clientAuthClaims = 
			new ClientAuthenticationClaims(iss, prn, aud, jti, exp);
		
		
		// Get optional iat claim
		IssueTime iat = new IssueTime();
		
		if (jsonObject.containsKey(iat.getClaimName())) {
			
			ClaimValueParser.parse(jsonObject, iat);
			jsonObject.remove(iat.getClaimName());
			clientAuthClaims.setIssueTime(iat);
		}
		
		
		// Get optional nbf claim
		NotBeforeTime nbf = new NotBeforeTime();
		
		if (jsonObject.containsKey(nbf.getClaimName())) {
		
			ClaimValueParser.parse(jsonObject, nbf);
			jsonObject.remove(nbf.getClaimName());
			clientAuthClaims.setNotBeforeTime(nbf);
		}
		
		
		// Add remaing claims as custom
		
		Iterator <Map.Entry<String,Object>> it = jsonObject.entrySet().iterator();
		
		while (it.hasNext()) {
		
			Map.Entry <String,Object> entry = it.next();
			
			GenericClaim gc = new GenericClaim(entry.getKey());
			gc.setClaimValue(entry.getValue());
			
			clientAuthClaims.addCustomClaim(gc);
		}
		
		return clientAuthClaims;
	}
}
