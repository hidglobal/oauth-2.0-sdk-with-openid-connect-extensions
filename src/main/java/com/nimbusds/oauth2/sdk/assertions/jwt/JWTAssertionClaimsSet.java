package com.nimbusds.oauth2.sdk.assertions.jwt;


import java.util.*;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;


/**
 * JSON Web Token (JWT) bearer assertion claims set for OAuth 2.0 client
 * authentication and authorisation grants.
 *
 * <p>Used for {@link ClientSecretJWT client secret JWT} and
 * {@link PrivateKeyJWT private key JWT} authentication at the Token endpoint.
 *
 * <p>Example JWT bearer assertion claims set for client authentication:
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
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523), section 3.
 * </ul>
 */
public class JWTAssertionClaimsSet {


	/**
	 * The names of the reserved JWT claims.
	 */
	private static final Set<String> reservedClaimsNames = new LinkedHashSet<>();


	static {
		reservedClaimsNames.add("iss");
		reservedClaimsNames.add("sub");
		reservedClaimsNames.add("aud");
		reservedClaimsNames.add("exp");
		reservedClaimsNames.add("nbf");
		reservedClaimsNames.add("iat");
		reservedClaimsNames.add("jti");
	}


	/**
	 * Gets the names of the reserved JWT bearer assertion claims.
	 *
	 * @return The names of the reserved JWT bearer assertion claims
	 *         (read-only set).
	 */
	public static Set<String> getReservedClaimsNames() {

		return Collections.unmodifiableSet(reservedClaimsNames);
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
	private final List<Audience> aud;


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
	 * Other optional custom claims.
	 */
	private final Map<String,Object> other;


	/**
	 * Creates a new JWT JWT bearer assertion claims set. The expiration
	 * time (exp) is set to five minutes from the current system time.
	 * Generates a default identifier (jti) for the JWT. The issued-at
	 * (iat) and not-before (nbf) claims are not set.
	 *
	 * @param iss The issuer identifier. Must not be {@code null}.
	 * @param sub The subject. Must not be {@code null}.
	 * @param aud The audience identifier, typically the URI of the
	 *            authorisation server's Token endpoint. Must not be
	 *            {@code null}.
	 */
	public JWTAssertionClaimsSet(final Issuer iss,
				     final Subject sub,
				     final Audience aud) {

		this(iss, sub, aud.toSingleAudienceList(), new Date(new Date().getTime() + 5*60*1000l), null, null, new JWTID(), null);
	}


	/**
	 * Creates a new JWT JWT bearer assertion claims set.
	 *
	 * @param iss   The issuer identifier. Must not be {@code null}.
	 * @param sub   The subject. Must not be {@code null}.
	 * @param aud   The audience, typically including the URI of the
	 *              authorisation server's token endpoint. Must not be
	 *              {@code null}.
	 * @param exp   The expiration time. Must not be {@code null}.
	 * @param nbf   The time before which the token must not be accepted
	 *              for processing, {@code null} if not specified.
	 * @param iat   The time at which the token was issued, {@code null} if
	 *              not specified.
	 * @param jti   Unique identifier for the JWT, {@code null} if not
	 *              specified.
	 * @param other Other custom claims to include, {@code null} if none.
	 */
	public JWTAssertionClaimsSet(final Issuer iss,
				     final Subject sub,
				     final List<Audience> aud,
				     final Date exp,
				     final Date nbf,
				     final Date iat,
				     final JWTID jti,
				     final Map<String,Object> other) {

		if (iss == null)
			throw new IllegalArgumentException("The issuer must not be null");

		this.iss = iss;

		if (sub == null)
			throw new IllegalArgumentException("The subject must not be null");

		this.sub = sub;

		
		if (aud == null || aud.isEmpty())
			throw new IllegalArgumentException("The audience must not be null or empty");

		this.aud = aud;


		if (exp == null)
			throw new IllegalArgumentException("The expiration time must not be null");

		this.exp = exp;

		this.nbf = nbf;
		this.iat = iat;
		this.jti = jti;

		this.other = other;
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
	 * Gets the audience. Corresponds to the {@code aud} claim.
	 *
	 * @return The audience, typically including the URI of the
	 *         authorisation server's token endpoint.
	 */
	public List<Audience> getAudience() {
	
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
	 * Gets the custom claims.
	 *
	 * @return The custom claims, {@code null} if not specified.
	 */
	public Map<String,Object> getCustomClaims() {

		return other;
	}
	
	
	/**
	 * Returns a JSON object representation of this JWT bearer assertion
	 * claims set.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("iss", iss.getValue());
		o.put("sub", sub.getValue());
		o.put("aud", Audience.toStringList(aud));
		o.put("exp", DateUtils.toSecondsSinceEpoch(exp));

		if (nbf != null)
			o.put("nbf", DateUtils.toSecondsSinceEpoch(nbf));
		
		if (iat != null)
			o.put("iat", DateUtils.toSecondsSinceEpoch(iat));
		
		if (jti != null)
			o.put("jti", jti.getValue());

		if (other != null) {
			o.putAll(other);
		}

		return o;
	}


	/**
	 * Returns a JSON Web Token (JWT) claims set representation of this
	 * JWT bearer assertion claims set.
	 *
	 * @return The JWT claims set.
	 */
	public JWTClaimsSet toJWTClaimsSet() {

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject(sub.getValue())
			.audience(Audience.toStringList(aud))
			.expirationTime(exp)
			.notBeforeTime(nbf) // optional
			.issueTime(iat) // optional
			.jwtID(jti != null ? jti.getValue() : null); // optional

		// Append custom claims if any
		if (other != null) {
			for (Map.Entry<String,?> entry: other.entrySet()) {
				builder = builder.claim(entry.getKey(), entry.getValue());
			}
		}

		return builder.build();
	}
	
	
	/**
	 * Parses a JWT bearer assertion claims set from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The JWT bearer assertion claims set.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a 
	 *                        JWT bearer assertion claims set.
	 */
	public static JWTAssertionClaimsSet parse(final JSONObject jsonObject)
		throws ParseException {
		
		// Parse required claims
		Issuer iss = new Issuer(JSONObjectUtils.getString(jsonObject, "iss"));
		Subject sub = new Subject(JSONObjectUtils.getString(jsonObject, "sub"));

		List<Audience> aud;

		if (jsonObject.get("aud") instanceof String) {
			aud = new Audience(JSONObjectUtils.getString(jsonObject, "aud")).toSingleAudienceList();
		} else {
			aud = Audience.create(JSONObjectUtils.getStringList(jsonObject, "aud"));
		}

		Date exp = DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(jsonObject, "exp"));


		// Parse optional claims

		Date nbf = null;

		if (jsonObject.containsKey("nbf"))
			nbf = DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(jsonObject, "nbf"));

		Date iat = null;

		if (jsonObject.containsKey("iat"))
			iat = DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(jsonObject, "iat"));

		JWTID jti = null;

		if (jsonObject.containsKey("jti"))
			jti = new JWTID(JSONObjectUtils.getString(jsonObject, "jti"));

		// Parse custom claims
		Map<String,Object> other = null;

		Set<String> customClaimNames = jsonObject.keySet();
		if (customClaimNames.removeAll(reservedClaimsNames)) {
			other = new LinkedHashMap<>();
			for (String claim: customClaimNames) {
				other.put(claim, jsonObject.get(claim));
			}
		}

		return new JWTAssertionClaimsSet(iss, sub, aud, exp, nbf, iat, jti, other);
	}


	/**
	 * Parses a JWT bearer assertion claims set from the specified JWT
	 * claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @return The JWT bearer assertion claims set.
	 *
	 * @throws ParseException If the JWT claims set couldn't be parsed to a 
	 *                        JWT bearer assertion claims set.
	 */
	public static JWTAssertionClaimsSet parse(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		return parse(jwtClaimsSet.toJSONObject());
	}
}
