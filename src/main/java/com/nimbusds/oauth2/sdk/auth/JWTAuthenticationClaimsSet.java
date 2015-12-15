package com.nimbusds.oauth2.sdk.auth;


import java.util.Date;
import java.util.List;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTClaimsSet;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;


/**
 * JWT client authentication claims set, serialisable to a JSON object and JWT 
 * claims set.
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
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
public class JWTAuthenticationClaimsSet extends JWTAssertionDetails {


	/**
	 * Creates a new JWT client authentication claims set. The expiration
	 * time (exp) is set to five minutes from the current system time.
	 * Generates a default identifier (jti) for the JWT. The issued-at
	 * (iat) and not-before (nbf) claims are not set.
	 *
	 * @param clientID The client identifier. Used to specify the issuer
	 *                 and the subject. Must not be {@code null}.
	 * @param aud      The audience identifier, typically the URI of the
	 *                 authorisation server's Token endpoint. Must not be
	 *                 {@code null}.
	 */
	public JWTAuthenticationClaimsSet(final ClientID clientID,
					  final Audience aud) {

		this(clientID, aud.toSingleAudienceList(), new Date(new Date().getTime() + 5*60* 1000L), null, null, new JWTID());
	}

	
	/**
	 * Creates a new JWT client authentication claims set.
	 *
	 * @param clientID The client identifier. Used to specify the issuer 
	 *                 and the subject. Must not be {@code null}.
	 * @param aud      The audience, typically including the URI of the
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
					  final List<Audience> aud,
					  final Date exp,
					  final Date nbf,
					  final Date iat,
					  final JWTID jti) {

		super(new Issuer(clientID.getValue()), new Subject(clientID.getValue()), aud, exp, nbf, iat, jti, null);
	}


	/**
	 * Gets the client identifier. Corresponds to the {@code iss} and
	 * {@code sub} claims.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {

		return new ClientID(getIssuer());
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
		
		JWTAssertionDetails assertion = JWTAssertionDetails.parse(jsonObject);

		return new JWTAuthenticationClaimsSet(
			new ClientID(assertion.getIssuer()), // iss=sub
			assertion.getAudience(),
			assertion.getExpirationTime(),
			assertion.getNotBeforeTime(),
			assertion.getIssueTime(),
			assertion.getJWTID());
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
	public static JWTAuthenticationClaimsSet parse(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		return parse(jwtClaimsSet.toJSONObject());
	}
}
