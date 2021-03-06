package com.nimbusds.oauth2.sdk.auth;


import java.net.URI;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Private key JWT authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT}.
 *
 * <p>Supported signature JSON Web Algorithms (JWAs) by this implementation:
 *
 * <ul>
 *     <li>RS256
 *     <li>RS384
 *     <li>RS512
 *     <li>PS256
 *     <li>PS384
 *     <li>PS512
 *     <li>ES256
 *     <li>ES384
 *     <li>ES512
 * </ul>
 *
 * <p>Example {@link com.nimbusds.oauth2.sdk.TokenRequest} with private key JWT
 * authentication:
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * grant_type=authorization_code&amp;
 * code=i1WsRn1uB1&amp;
 * client_id=s6BhdRkqt3&amp;
 * client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&amp;
 * client_assertion=PHNhbWxwOl...[omitted for brevity]...ZT
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521).
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523)
 * </ul>
 */
@Immutable
public final class PrivateKeyJWT extends JWTAuthentication {


	/**
	 * Returns the supported signature JSON Web Algorithms (JWAs).
	 *
	 * @return The supported JSON Web Algorithms (JWAs).
	 */
	public static Set<JWSAlgorithm> supportedJWAs() {

		Set<JWSAlgorithm> supported = new HashSet<>();
		supported.addAll(JWSAlgorithm.Family.RSA);
		supported.addAll(JWSAlgorithm.Family.EC);
		return Collections.unmodifiableSet(supported);
	}


	/**
	 * Creates a new RSA private key JWT authentication. The expiration
	 * time (exp) is set to five minutes from the current system time.
	 * Generates a default identifier (jti) for the JWT. The issued-at
	 * (iat) and not-before (nbf) claims are not set.
	 *
	 * @param clientID      The client identifier. Must not be
	 *                      {@code null}.
	 * @param tokenEndpoint The token endpoint URI of the authorisation
	 *                      server. Must not be {@code null}.
	 * @param jwsAlgorithm  The expected RSA signature algorithm (RS256,
	 *                      RS384 or RS512) for the private key JWT
	 *                      assertion. Must be supported and not
	 *                      {@code null}.
	 * @param rsaPrivateKey The RSA private key. Must not be {@code null}.
	 * @param keyID         Optional identifier for the RSA key, to aid
	 *                      key selection at the authorisation server.
	 *                      Recommended. {@code null} if not specified.
	 * @param jcaProvider   Optional specific JCA provider, {@code null} to
	 *                      use the default one.
	 *
	 * @throws JOSEException If RSA signing failed.
	 */
	public PrivateKeyJWT(final ClientID clientID,
			     final URI tokenEndpoint,
			     final JWSAlgorithm jwsAlgorithm,
			     final RSAPrivateKey rsaPrivateKey,
			     final String keyID,
			     final Provider jcaProvider)
		throws JOSEException {

		this(new JWTAuthenticationClaimsSet(clientID, new Audience(tokenEndpoint.toString())),
			jwsAlgorithm,
			rsaPrivateKey,
			keyID,
			jcaProvider);
	}


	/**
	 * Creates a new RSA private key JWT authentication.
	 *
	 * @param jwtAuthClaimsSet The JWT authentication claims set. Must not
	 *                         be {@code null}.
	 * @param jwsAlgorithm     The expected RSA signature algorithm (RS256,
	 *                         RS384 or RS512) for the private key JWT
	 *                         assertion. Must be supported and not
	 *                         {@code null}.
	 * @param rsaPrivateKey    The RSA private key. Must not be
	 *                         {@code null}.
	 * @param keyID            Optional identifier for the RSA key, to aid
	 *                         key selection at the authorisation server.
	 *                         Recommended. {@code null} if not specified.
	 * @param jcaProvider      Optional specific JCA provider, {@code null}
	 *                         to use the default one.
	 *
	 * @throws JOSEException If RSA signing failed.
	 */
	public PrivateKeyJWT(final JWTAuthenticationClaimsSet jwtAuthClaimsSet,
			     final JWSAlgorithm jwsAlgorithm,
			     final RSAPrivateKey rsaPrivateKey,
			     final String keyID,
			     final Provider jcaProvider)
		throws JOSEException {

		this(JWTAssertionFactory.create(jwtAuthClaimsSet, jwsAlgorithm, rsaPrivateKey, keyID, jcaProvider));
	}


	/**
	 * Creates a new EC private key JWT authentication. The expiration
	 * time (exp) is set to five minutes from the current system time.
	 * Generates a default identifier (jti) for the JWT. The issued-at
	 * (iat) and not-before (nbf) claims are not set.
	 *
	 * @param clientID      The client identifier. Must not be
	 *                      {@code null}.
	 * @param tokenEndpoint The token endpoint URI of the authorisation
	 *                      server. Must not be {@code null}.
	 * @param jwsAlgorithm  The expected EC signature algorithm (ES256,
	 *                      ES384 or ES512) for the private key JWT
	 *                      assertion. Must be supported and not
	 *                      {@code null}.
	 * @param ecPrivateKey  The EC private key. Must not be {@code null}.
	 * @param keyID         Optional identifier for the EC key, to aid key
	 *                      selection at the authorisation server.
	 *                      Recommended. {@code null} if not specified.
	 * @param jcaProvider   Optional specific JCA provider, {@code null} to
	 *                      use the default one.
	 *
	 * @throws JOSEException If RSA signing failed.
	 */
	public PrivateKeyJWT(final ClientID clientID,
			     final URI tokenEndpoint,
			     final JWSAlgorithm jwsAlgorithm,
			     final ECPrivateKey ecPrivateKey,
			     final String keyID,
			     final Provider jcaProvider)
		throws JOSEException {

		this(new JWTAuthenticationClaimsSet(clientID, new Audience(tokenEndpoint.toString())),
			jwsAlgorithm,
			ecPrivateKey,
			keyID,
			jcaProvider);
	}
	
	
	/**
	 * Creates a new EC private key JWT authentication.
	 *
	 * @param jwtAuthClaimsSet The JWT authentication claims set. Must not
	 *                         be {@code null}.
	 * @param jwsAlgorithm     The expected ES signature algorithm (ES256,
	 *                         ES384 or ES512) for the private key JWT
	 *                         assertion. Must be supported and not
	 *                         {@code null}.
	 * @param ecPrivateKey     The EC private key. Must not be
	 *                         {@code null}.
	 * @param keyID            Optional identifier for the EC key, to aid
	 *                         key selection at the authorisation server.
	 *                         Recommended. {@code null} if not specified.
	 * @param jcaProvider      Optional specific JCA provider, {@code null}
	 *                         to use the default one.
	 *
	 * @throws JOSEException If RSA signing failed.
	 */
	public PrivateKeyJWT(final JWTAuthenticationClaimsSet jwtAuthClaimsSet,
			     final JWSAlgorithm jwsAlgorithm,
			     final ECPrivateKey ecPrivateKey,
			     final String keyID,
			     final Provider jcaProvider)
		throws JOSEException {

		this(JWTAssertionFactory.create(jwtAuthClaimsSet, jwsAlgorithm, ecPrivateKey, keyID, jcaProvider));
	}


	/**
	 * Creates a new private key JWT authentication.
	 *
	 * @param clientAssertion The client assertion, corresponding to the
	 *                        {@code client_assertion} parameter, as a
	 *                        supported RSA or ECDSA-signed JWT. Must be
	 *                        signed and not {@code null}.
	 */
	public PrivateKeyJWT(final SignedJWT clientAssertion) {
	
		super(ClientAuthenticationMethod.PRIVATE_KEY_JWT, clientAssertion);

		JWSAlgorithm alg = clientAssertion.getHeader().getAlgorithm();

		if (! JWSAlgorithm.Family.RSA.contains(alg) && ! JWSAlgorithm.Family.EC.contains(alg))
			throw new IllegalArgumentException("The client assertion JWT must be RSA or ECDSA-signed (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 or ES512)");
	}
	
	
	/**
	 * Parses the specified parameters map for a private key JSON Web Token
	 * (JWT) authentication. Note that the parameters must not be
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @param params The parameters map to parse. The private key JSON
	 *               Web Token (JWT) parameters must be keyed under 
	 *               "client_assertion" and "client_assertion_type". The 
	 *               map must not be {@code null}.
	 *
	 * @return The private key JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the parameters map couldn't be parsed to a 
	 *                        private key JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static PrivateKeyJWT parse(final Map<String,String> params)
		throws ParseException {
	
		JWTAuthentication.ensureClientAssertionType(params);
		
		SignedJWT clientAssertion = JWTAuthentication.parseClientAssertion(params);

		PrivateKeyJWT privateKeyJWT;

		try {
			privateKeyJWT = new PrivateKeyJWT(clientAssertion);

		}catch (IllegalArgumentException e) {

			throw new ParseException(e.getMessage(), e);
		}

		// Check that the top level client_id matches the assertion subject + issuer

		ClientID clientID = JWTAuthentication.parseClientID(params);

		if (clientID != null) {

			if (! clientID.equals(privateKeyJWT.getClientID()))
				throw new ParseException("The client identifier doesn't match the client assertion subject / issuer");
		}

		return privateKeyJWT;
	}
	
	
	/**
	 * Parses a private key JSON Web Token (JWT) authentication from the 
	 * specified {@code application/x-www-form-urlencoded} encoded 
	 * parameters string.
	 *
	 * @param paramsString The parameters string to parse. The private key
	 *                     JSON Web Token (JWT) parameters must be keyed 
	 *                     under "client_assertion" and 
	 *                     "client_assertion_type". The string must not be 
	 *                     {@code null}.
	 *
	 * @return The private key JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the parameters string couldn't be parsed 
	 *                        to a private key JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static PrivateKeyJWT parse(final String paramsString)
		throws ParseException {
		
		Map<String,String> params = URLUtils.parseParameters(paramsString);
		
		return parse(params);
	}
	
	
	/**
	 * Parses the specified HTTP POST request for a private key JSON Web 
	 * Token (JWT) authentication.
	 *
	 * @param httpRequest The HTTP POST request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    {@code application/x-www-form-urlencoded} encoded 
	 *                    parameters string in the entity body. The private 
	 *                    key JSON Web Token (JWT) parameters must be 
	 *                    keyed under "client_assertion" and 
	 *                    "client_assertion_type".
	 *
	 * @return The private key JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the HTTP request header couldn't be parsed
	 *                        to a private key JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static PrivateKeyJWT parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		return parse(httpRequest.getQueryParameters());
	}
}
