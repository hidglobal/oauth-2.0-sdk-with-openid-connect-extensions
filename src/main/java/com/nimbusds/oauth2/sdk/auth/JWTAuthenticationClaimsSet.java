package com.nimbusds.oauth2.sdk.auth;


import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * JWT client authentication claims set, serialisable to a JSON object and JWT 
 * claims set. This class is immutable.
 *
 * <p>Used for {@link ClientSecretJWT client secret JWT} and 
 * {@link PrivateKeyJWT private key JWT} authentication at the Token endpoint.
 *
 * <p>Example client authentication claims set:
 *
 * <pre>
 * {
 *   "iss" : "http://client.example.com",
 *   "sub" : "http://client.example.com",
 *   "aud" : [ "http://idp.example.com/token" ],
 *   "jti" : "d396036d-c4d9-40d8-8e98-f7e8327002d9",
 *   "exp" : 1311281970,
 *   "iat" : 1311280970
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section-3.2.1.
 *     <li>JSON Web Token (JWT) Bearer Token Profiles for OAuth 2.0 
 *         (draft-ietf-oauth-jwt-bearer-04)
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class JWTAuthenticationClaimsSet {


	/**
	 * The names of the reserved client authentication claims.
	 */
	private static final Set<String> reservedClaimNames = new LinkedHashSet<String>();
	
	
	static {
		reservedClaimNames.add("iss");
		reservedClaimNames.add("sub");
		reservedClaimNames.add("aud");
		reservedClaimNames.add("exp");
		reservedClaimNames.add("nbf");
		reservedClaimNames.add("iat");
		reservedClaimNames.add("jti");
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
	private final Issuer iss;
	
	
	/**
	 * The subject (required).
	 */
	private final Subject sub;
	
	
	/**
	 * The audience that this token is intended for (required).
	 */
	private final Audience aud;
	
	
	/**
	 * The expiration time that limits the time window during which the JWT 
	 * can be used (required). The serialised value is number of seconds 
	 * from 1970-01-01T0:0:0Z as measured in UTC until the desired 
	 * date/time.
	 */
	private final Date exp;


	/**
	 * The time before which this token must not be accepted for 
	 * processing (optional). The serialised value is number of seconds 
	 * from 1970-01-01T0:0:0Z as measured in UTC until the desired 
	 * date/time.
	 */
	private final Date nbf;
	
	
	/**
	 * The time at which this token was issued (optional). The serialised
	 * value is number of seconds from 1970-01-01T0:0:0Z as measured in UTC 
	 * until the desired date/time.
	 */
	private final Date iat;


	/**
	 * Unique identifier for the JWT (optional). The JWT ID may be used by
	 * implementations requiring message de-duplication for one-time use 
	 * assertions. 
	 */
	private final JWTID jti;
	
	
	/**
	 * Creates a new JWT client authentication claims set.
	 *
	 * @param clientID The client identifier. Used to specify the issuer 
	 *                 and the subject. Must not be {@code null}.
	 * @param aud      The audience identifier, typically the URL of the 
	 *                 authorisation server's Token endpoint. Must not be 
	 *                 {@code null}.
	 * @param exp      The expiration time. Must not be {@code null}.
	 * @param nbf      The time before which the token must not be 
	 *                 accepted for processing, {@code null} if not
	 *                 specified.
	 * @param iat      The time at which the token was issued, 
	 *                 {@code null} if not specified.
	 * @param jti      Unique identifier for the JWT, {@code null} if
	 *                 not specified.
	 */
	public JWTAuthenticationClaimsSet(final ClientID clientID,
					  final Audience aud,
					  final Date exp,
					  final Date nbf,
					  final Date iat,
					  final JWTID jti) {

		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");

		iss = new Issuer(clientID.value());

		sub = new Subject(clientID.value());

		
		if (aud == null)
			throw new IllegalArgumentException("The audience must not be null");

		this.aud = aud;


		if (exp == null)
			throw new IllegalArgumentException("The expiration time must not be null");

		this.exp = exp;


		this.nbf = nbf;
		this.iat = iat;
		this.jti = jti;
	}


	/**
	 * Gets the client identifier. Corresponds to the {@code iss} and
	 * {@code sub} claims.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {

		return new ClientID(iss.value());
	}

	
	
	/**
	 * Gets the issuer. Corresponds to the {@code iss} claim.
	 *
	 * @return The issuer. Contains the identifier of the OAuth client.
	 */
	public Issuer getIssuer() {
	
		return iss;
	}
	
	
	/**
	 * Gets the subject. Corresponds to the {@code sub} claim.
	 *
	 * @return The subject. Contains the identifier of the OAuth client.
	 */
	public Subject getSubject() {
	
		return sub;
	}
	
	
	/**
	 * Gets the audience. Corresponds to the {@code aud} claim 
	 * (single-valued).
	 *
	 * @return The audience, typically the URL of the authorisation 
	 *         server's token endpoint.
	 */
	public Audience getAudience() {
	
		return aud;
	}


	/**
	 * Gets the expiration time. Corresponds to the {@code exp} claim.
	 *
	 * @return The expiration time.
	 */
	public Date getExpirationTime() {
	
		return exp;
	}
	
	
	/**
	 * Gets the not-before time. Corresponds to the {@code nbf} claim.
	 *
	 * @return The not-before time, {@code null} if not specified.
	 */
	public Date getNotBeforeTime() {
	
		return nbf;
	}


	/**
	 * Gets the optional issue time. Corresponds to the {@code iat} claim.
	 *
	 * @return The issued-at time, {@code null} if not specified.
	 */
	public Date getIssueTime() {
	
		return iat;
	}
	
	
	/**
	 * Gets the identifier for the JWT. Corresponds to the {@code jti} 
	 * claim.
	 *
	 * @return The identifier for the JWT, {@code null} if not specified.
	 */
	public JWTID getJWTID() {
	
		return jti;
	}
	
	
	/**
	 * Returns a JSON object representation of this JWT client 
	 * authentication claims set.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("iss", iss.value());
		o.put("sub", sub.value());

		List<Object> audList = new LinkedList<Object>();
		audList.add(exp.getTime() / 1000);
		o.put("aud", audList);

		o.put("exp", exp.getTime() / 1000);

		if (nbf != null)
			o.put("nbf", nbf.getTime() / 1000);
		
		if (iat != null)
			o.put("iat", iat.getTime() / 1000);
		
		if (jti != null)
			o.put("jti", jti.value());
		
		return o;
	}


	/**
	 * Returns a JSON Web Token (JWT) claims set representation of this
	 * client authentication claims set.
	 *
	 * @return The JWT claims set.
	 */
	public JWTClaimsSet toJWTClaimsSet() {

		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();

		jwtClaimsSet.setIssuer(iss.value());
		jwtClaimsSet.setSubject(sub.value());

		List<String> audList = new LinkedList<String>();
		audList.add(aud.value());

		jwtClaimsSet.setAudience(audList);
		jwtClaimsSet.setExpirationTime(exp);

		if (nbf != null)
			jwtClaimsSet.setNotBeforeTime(nbf);
		
		if (iat != null)
			jwtClaimsSet.setIssueTime(iat);
		
		if (jti != null)
			jwtClaimsSet.setJWTID(jti.value());

		return jwtClaimsSet;
	}
	
	
	/**
	 * Parses a JWT client authentication claims set from the specified 
	 * JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client authentication claims set.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a 
	 *                        client authentication claims set.
	 */
	public static JWTAuthenticationClaimsSet parse(final JSONObject jsonObject)
		throws ParseException {
		
		// Parse required claims
		Issuer iss = new Issuer(JSONObjectUtils.getString(jsonObject, "iss"));
		Subject sub = new Subject(JSONObjectUtils.getString(jsonObject, "sub"));

		Audience aud = null;

		if (jsonObject.get("aud") instanceof String) {

			aud = new Audience(JSONObjectUtils.getString(jsonObject, "aud"));
		}
		else {
			String[] audList = JSONObjectUtils.getStringArray(jsonObject, "aud");

			if (audList.length > 1)
				throw new ParseException("Multiple audiences (aud) not supported");

			aud = new Audience(audList[0]);
		}

		Date exp = new Date(JSONObjectUtils.getLong(jsonObject, "exp") * 1000);


		// Parse optional claims

		Date nbf = null;

		if (jsonObject.containsKey("nbf"))
			nbf = new Date(JSONObjectUtils.getLong(jsonObject, "nbf") * 1000);

		Date iat = null;

		if (jsonObject.containsKey("iat"))
			iat = new Date(JSONObjectUtils.getLong(jsonObject, "iat") * 1000);

		JWTID jti = null;

		if (jsonObject.containsKey("jti"))
			jti = new JWTID(JSONObjectUtils.getString(jsonObject, "jti"));


		// Check client ID

		if (iss.value() != sub.value())
			throw new ParseException("JWT issuer and subject must have the same client ID");

		ClientID clientID = new ClientID(iss.value());

		return new JWTAuthenticationClaimsSet(clientID, aud, exp, nbf, iat, jti);
	}


	/**
	 * Parses a JWT client authentication claims set from the specified JWT 
	 * claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @return The client authentication claims set.
	 *
	 * @throws ParseException If the JWT claims set couldn't be parsed to a 
	 *                        client authentication claims set.
	 */
	public static JWTAuthenticationClaimsSet parse(final ReadOnlyJWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		return parse(jwtClaimsSet.toJSONObject());
	}
}
