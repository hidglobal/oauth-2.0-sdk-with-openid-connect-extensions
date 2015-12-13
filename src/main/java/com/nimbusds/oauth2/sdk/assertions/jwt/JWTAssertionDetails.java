package com.nimbusds.oauth2.sdk.assertions.jwt;


import java.util.*;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.assertions.AssertionDetails;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;


/**
 * JSON Web Token (JWT) bearer assertion details (claims set) for OAuth 2.0
 * client authentication and authorisation grants.
 *
 * <p>Used for {@link ClientSecretJWT client secret JWT} and
 * {@link PrivateKeyJWT private key JWT} authentication at the Token endpoint
 * as well as {@link com.nimbusds.oauth2.sdk.JWTBearerGrant JWT bearer
 * assertion grants}.
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
@Immutable
public class JWTAssertionDetails extends AssertionDetails {


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
	 * The time before which this token must not be accepted for
	 * processing (optional). The serialised value is number of seconds
	 * from 1970-01-01T0:0:0Z as measured in UTC until the desired
	 * date/time.
	 */
	private final Date nbf;


	/**
	 * Other optional custom claims.
	 */
	private final Map<String,Object> other;


	/**
	 * Creates a new JWT bearer assertion details (claims set) instance.
	 * The expiration time (exp) is set to five minutes from the current
	 * system time. Generates a default identifier (jti) for the JWT. The
	 * issued-at (iat) and not-before (nbf) claims are not set.
	 *
	 * @param iss The issuer identifier. Must not be {@code null}.
	 * @param sub The subject. Must not be {@code null}.
	 * @param aud The audience identifier, typically the URI of the
	 *            authorisation server's Token endpoint. Must not be
	 *            {@code null}.
	 */
	public JWTAssertionDetails(final Issuer iss,
				   final Subject sub,
				   final Audience aud) {

		this(iss, sub, aud.toSingleAudienceList(), new Date(new Date().getTime() + 5*60*1000L), null, null, new JWTID(), null);
	}


	/**
	 * Creates a new JWT bearer assertion details (claims set) instance.
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
	public JWTAssertionDetails(final Issuer iss,
				   final Subject sub,
				   final List<Audience> aud,
				   final Date exp,
				   final Date nbf,
				   final Date iat,
				   final JWTID jti,
				   final Map<String,Object> other) {

		super(iss, sub, aud, iat, exp, jti);
		this.nbf = nbf;
		this.other = other;
	}
	
	
	/**
	 * Returns the optional not-before time. Corresponds to the {@code nbf}
	 * claim.
	 *
	 * @return The not-before time, {@code null} if not specified.
	 */
	public Date getNotBeforeTime() {
	
		return nbf;
	}


	/**
	 * Returns the optional assertion identifier, as a JWT ID. Corresponds
	 * to the {@code jti} claim.
	 *
	 * @see #getID()
	 *
	 * @return The optional JWT ID, {@code null} if not specified.
	 */
	public JWTID getJWTID() {

		Identifier id = getID();
		return id != null ? new JWTID(id.getValue()) : null;
	}


	/**
	 * Returns the custom claims.
	 *
	 * @return The custom claims, {@code null} if not specified.
	 */
	public Map<String,Object> getCustomClaims() {

		return other;
	}
	
	
	/**
	 * Returns a JSON object representation of this JWT bearer assertion
	 * details.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("iss", getIssuer().getValue());
		o.put("sub", getSubject().getValue());
		o.put("aud", Audience.toStringList(getAudience()));
		o.put("exp", DateUtils.toSecondsSinceEpoch(getExpirationTime()));

		if (nbf != null)
			o.put("nbf", DateUtils.toSecondsSinceEpoch(nbf));
		
		if (getIssueTime() != null)
			o.put("iat", DateUtils.toSecondsSinceEpoch(getIssueTime()));
		
		if (getID() != null)
			o.put("jti", getID().getValue());

		if (other != null) {
			o.putAll(other);
		}

		return o;
	}


	/**
	 * Returns a JSON Web Token (JWT) claims set representation of this
	 * JWT bearer assertion details.
	 *
	 * @return The JWT claims set.
	 */
	public JWTClaimsSet toJWTClaimsSet() {

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
			.issuer(getIssuer().getValue())
			.subject(getSubject().getValue())
			.audience(Audience.toStringList(getAudience()))
			.expirationTime(getExpirationTime())
			.notBeforeTime(nbf) // optional
			.issueTime(getIssueTime()) // optional
			.jwtID(getID() != null ? getJWTID().getValue() : null); // optional

		// Append custom claims if any
		if (other != null) {
			for (Map.Entry<String,?> entry: other.entrySet()) {
				builder = builder.claim(entry.getKey(), entry.getValue());
			}
		}

		return builder.build();
	}
	
	
	/**
	 * Parses a JWT bearer assertion details (claims set) instance from the
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The JWT bearer assertion details.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a 
	 *                        JWT bearer assertion details instance.
	 */
	public static JWTAssertionDetails parse(final JSONObject jsonObject)
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

		return new JWTAssertionDetails(iss, sub, aud, exp, nbf, iat, jti, other);
	}


	/**
	 * Parses a JWT bearer assertion details instance from the specified
	 * JWT claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @return The JWT bearer assertion details.
	 *
	 * @throws ParseException If the JWT claims set couldn't be parsed to a 
	 *                        JWT bearer assertion details instance.
	 */
	public static JWTAssertionDetails parse(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		return parse(jwtClaimsSet.toJSONObject());
	}
}
