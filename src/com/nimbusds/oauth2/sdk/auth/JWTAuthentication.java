package com.nimbusds.oauth2.sdk.auth;


import java.util.HashMap;
import java.util.Map;

import javax.mail.internet.ContentType;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;

import com.nimbusds.oauth2.sdk.id.ClientID;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Base abstract class for JSON Web Token (JWT) based client authentication at 
 * the Token endpoint.
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
 * @version $version$ (2013-01-18)
 */
public abstract class JWTAuthentication extends ClientAuthentication {


	/**
	 * The expected client assertion type, corresponding to the
	 * {@code client_assertion_type} parameter. This is a URN string set to
	 * "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
	 */
	public static final String CLIENT_ASSERTION_TYPE = 
		"urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
	

	/**
	 * The client assertion, corresponding to the {@link client_assertion}
	 * parameter. The assertion is in the form of a signed JWT.
	 */
	private final SignedJWT clientAssertion;
	
	
	/**
	 * Optional client identifier, corresponding to the {@link client_id}
	 * parameter.
	 */
	private final ClientID clientID;
	
	
	/**
	 * Creates a new JSON Web Token (JWT) based client authentication.
	 *
	 * @param method          The client authentication method. Must not be
	 *                        {@code null}.
	 * @param clientAssertion The client assertion, corresponding to the
	 *                        {@code client_assertion} parameter, in the 
	 *                        form of a signed JSON Web Token (JWT). Must 
	 *                        not be {@code null}.
	 * @param clientID        Optional client identifier, corresponding to
	 *                        the {@code client_id} parameter. {@code null}
	 *                        if not specified.
	 */
	protected JWTAuthentication(final ClientAuthenticationMethod method, 
	                            final SignedJWT clientAssertion,
	                            final ClientID clientID) {
	
		super(method);
	
		if (clientAssertion == null)
			throw new IllegalArgumentException("The client assertion JWT must not be null");
			
		this.clientAssertion = clientAssertion;
		
		this.clientID = clientID;
	}
	
	
	/**
	 * Gets the client assertion, corresponding to the 
	 * {@code client_assertion} parameter.
	 *
	 * @return The client assertion, in the form of a signed JSON Web Token 
	 *         (JWT).
	 */
	public SignedJWT getClientAssertion() {
	
		return clientAssertion;
	}
	
	
	/**
	 * Gets the optional client identifier, corresponding to the
	 * {@code client_id} parameter.
	 *
	 * @return The client identifier, {@code null} if not specified.
	 */
	public ClientID getClientID() {
	
		return clientID;
	}
	
	
	/**
	 * Gets the client authentication claims set contained in the client
	 * assertion JSON Web Token (JWT).
	 *
	 * @return The client authentication claims.
	 *
	 * @throws ParseException If the client assertion JSON Web Token (JWT)
	 *                        doesn't contain a client authentication
	 *                        claims set.
	 */
	public JWTAuthenticationClaimsSet getJWTAuthenticationClaimsSet()
		throws ParseException {
	
		JSONObject claimsSet = null;
		
		try {
			claimsSet = clientAssertion.getJWTClaimsSet().toJSONObject();
			
		} catch (java.text.ParseException e) {
		
			throw new ParseException("Couldn't retrieve JSON object from the client assertion JWT");
		}
		
		if (claimsSet == null)
			throw new ParseException("Couldn't retrieve JSON object from the client assertion JWT");
		
		return JWTAuthenticationClaimsSet.parse(claimsSet);
	}
	
	
	/**
	 * Returns the parameter representation of this JSON Web Token (JWT) 
	 * based client authentication. Note that the parameters are not 
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * <p>Parameters map:
	 *
	 * <pre>
	 * "client_assertion" -> [serialised-JWT]
	 * "client_assertion_type" -> "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	 * "client_id" -> [optional-client-id]
	 * </pre>
	 *
	 * @return The parameters map, with keys "client_assertion",
	 *         "client_assertion_type" and "client_id".
	 *
	 * @throws SerializeException If the signed JWT couldn't be serialised
	 *                            to a client assertion string.
	 */
	public Map<String,String> toParameters()
		throws SerializeException {
	
		Map<String,String> params = new HashMap<String,String>();
		
		try {
			params.put("client_assertion", clientAssertion.serialize());
		
		} catch (IllegalStateException e) {
		
			throw new SerializeException("Couldn't serialize JWT to a client assertion string: " + e.getMessage(), e);
		}	
		
		params.put("client_assertion_type", CLIENT_ASSERTION_TYPE);
		
		if (clientID != null)
			params.put("client_id", clientID.getValue());
		
		return params;
	}
	
	
	@Override
	public void apply(final HTTPRequest httpRequest)
		throws SerializeException {
		
		if (httpRequest.getMethod() != HTTPRequest.Method.POST)
			throw new SerializeException("The HTTP request method must be POST");
		
		ContentType ct = httpRequest.getContentType();
		
		if (ct == null)
			throw new SerializeException("Missing HTTP Content-Type header");
		
		if (! ct.match(CommonContentTypes.APPLICATION_URLENCODED))
			throw new SerializeException("The HTTP Content-Type header must be " + CommonContentTypes.APPLICATION_URLENCODED);
		
		Map <String,String> params = httpRequest.getQueryParameters();
		
		params.putAll(toParameters());
		
		String queryString = URLUtils.serializeParameters(params);
		
		httpRequest.setQuery(queryString);
	}
	
	
	/**
	 * Ensures the specified parameters map contains an entry with key 
	 * "client_assertion_type" pointing to a string that equals the expected
	 * {@link #CLIENT_ASSERTION_TYPE}. This method is intended to aid 
	 * parsing of JSON Web Token (JWT) based client authentication objects.
	 *
	 * @param params The parameters map to check. The parameters must not be
	 *               {@code null} and 
	 *               {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @throws ParseException If expected "client_assertion_type" entry 
	 *                        wasn't found.
	 */
	protected static void ensureClientAssertionType(final Map<String,String> params)
		throws ParseException {
		
		final String clientAssertionType = params.get("client_assertion_type");
		
		if (clientAssertionType == null)
			throw new ParseException("Missing \"client_assertion_type\" parameter");
		
		if (! clientAssertionType.equals(CLIENT_ASSERTION_TYPE))
			throw new ParseException("Invalid \"client_assertion_type\" parameter, must be " + CLIENT_ASSERTION_TYPE);
	}
	
	
	/**
	 * Parses the specified parameters map for a client assertion. This
	 * method is intended to aid parsing of JSON Web Token (JWT) based 
	 * client authentication objects.
	 *
	 * @param params The parameters map to parse. It must contain an entry
	 *               with key "client_assertion" pointing to a string that
	 *               represents a signed serialised JSON Web Token (JWT).
	 *               The parameters must not be {@code null} and
	 *               {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @return The client assertion as a signed JSON Web Token (JWT).
	 *
	 * @throws ParseException If a "client_assertion" entry couldn't be
	 *                        retrieved from the parameters map.
	 */
	protected static SignedJWT parseClientAssertion(final Map<String,String> params)
		throws ParseException {
		
		final String clientAssertion = params.get("client_assertion");
		
		if (clientAssertion == null)
			throw new ParseException("Missing \"client_assertion\" parameter");
		
		try {
			return SignedJWT.parse(clientAssertion);
			
		} catch (java.text.ParseException e) {
		
			throw new ParseException("Invalid \"client_assertion\" JWT: " + e.getMessage(), e);
		}
	}
	
	/**
	 * Parses the specified parameters map for an optional client 
	 * identifier. This method is intended to aid parsing of JSON Web Token 
	 * (JWT) based client authentication objects.
	 *
	 * @param params The parameters map to parse. It may contain an entry
	 *               with key "client_id" pointing to a string that 
	 *               represents the client identifier. The parameters must 
	 *               not be {@code null} and 
	 *               {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @return The client identifier, {@code null} if not specified.
	 */
	protected static ClientID parseClientID(final Map<String,String> params) {
		
		String clientIDString = params.get("client_id");

		if (clientIDString == null)
			return null;

		else
			return new ClientID(clientIDString);
	}
	
	
	/**
	 * Parses the specified HTTP request for a JSON Web Token (JWT) based
	 * client authentication.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be {@code null}.
	 *
	 * @return The JSON Web Token (JWT) based client authentication.
	 *
	 * @throws ParseException If a JSON Web Token (JWT) based client 
	 *                        authentication couldn't be retrieved from the
	 *                        HTTP request.
	 */
	public static JWTAuthentication parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing HTTP POST request entity body");
		
		Map<String,String> params = URLUtils.parseParameters(query);
		
		JWSAlgorithm alg = parseClientAssertion(params).getHeader().getAlgorithm();
			
		if (ClientSecretJWT.getSupportedJWAs().contains(alg))
			return ClientSecretJWT.parse(params);
				
		else if (PrivateKeyJWT.getSupportedJWAs().contains(alg))
			return PrivateKeyJWT.parse(params);
			
		else
			throw new ParseException("Unsupported signed JWT algorithm: " + alg);
	}
}
