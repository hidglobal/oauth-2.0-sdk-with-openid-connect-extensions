package com.nimbusds.openid.connect.sdk.op;


import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.ThreadSafe;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.util.JWTDecoder;
import com.nimbusds.openid.connect.sdk.util.Resource;
import com.nimbusds.openid.connect.sdk.util.ResourceRetriever;


/**
 * Resolves the final OpenID Connect authentication request by superseding its
 * parameters with those found in the optional OpenID Connect request object.
 * The request object is encoded as a JSON Web Token (JWT) and can be specified 
 * directly (inline) using the {@code request} parameter, or by URL using the 
 * {@code request_uri} parameter.
 *
 * <p>To process signed (JWS) and optionally encrypted (JWE) request object 
 * JWTs a {@link com.nimbusds.openid.connect.sdk.util.JWTDecoder JWT decoder}
 * for the expected JWS / JWE algorithms must be provided at construction time.
 *
 * <p>To fetch OpenID Connect request objects specified by URL a
 * {@link com.nimbusds.openid.connect.sdk.util.ResourceRetriever JWT retriever}
 * must be provided, otherwise only inlined request objects can be processed.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 6.
 * </ul>
 */
@ThreadSafe
public class AuthenticationRequestResolver {


	/**
	 * The JWT decoder.
	 */
	private final JWTDecoder jwtDecoder;


	/**
	 * Optional retriever for JWTs passed by URL.
	 */
	private final ResourceRetriever jwtRetriever;


	/**
	 * Creates a new minimal OpenID Connect authentication request
	 * resolver. It will not process OpenID Connect request objects and
	 * will throw a {@link ResolveException} if the authentication request
	 * includes a {@code request} or {@code request_uri} parameter.
	 */
	public AuthenticationRequestResolver() {

		jwtDecoder = null;
		jwtRetriever = null;
	}
	
	
	/**
	 * Creates a new OpenID Connect authentication request resolver that
	 * supports OpenID Connect request objects passed by value (using the
	 * authentication {@code request} parameter). It will throw a
	 * {@link ResolveException} if the authentication request includes a
	 * {@code request_uri} parameter.
	 *
	 * @param jwtDecoder A configured JWT decoder providing JWS validation 
	 *                   and optional JWE decryption of the request
	 *                   objects. Must not be {@code null}.
	 */
	public AuthenticationRequestResolver(final JWTDecoder jwtDecoder) {

		if (jwtDecoder == null)
			throw new IllegalArgumentException("The JWT decoder must not be null");

		this.jwtDecoder = jwtDecoder;

		jwtRetriever = null;
	}
	
	
	/**
	 * Creates a new OpenID Connect request object resolver that supports
	 * OpenID Connect request objects passed by value (using the
	 * authentication {@code request} parameter) or by reference (using the
	 * authentication {@code request_uri} parameter).
	 * 
	 * @param jwtDecoder   A configured JWT decoder providing JWS 
	 *                     validation and optional JWE decryption of the
	 *                     request objects. Must not be {@code null}.
	 * @param jwtRetriever A configured JWT retriever for OpenID Connect
	 *                     request objects passed by URI. Must not be
	 *                     {@code null}.
	 */
	public AuthenticationRequestResolver(final JWTDecoder jwtDecoder,
					     final ResourceRetriever jwtRetriever) {

		if (jwtDecoder == null)
			throw new IllegalArgumentException("The JWT decoder must not be null");

		this.jwtDecoder = jwtDecoder;


		if (jwtRetriever == null)
			throw new IllegalArgumentException("The JWT retriever must not be null");

		this.jwtRetriever = jwtRetriever;
	}
	
	
	/**
	 * Gets the JWT decoder.
	 *
	 * @return The JWT decoder, {@code null} if not specified.
	 */
	public JWTDecoder getJWTDecoder() {
	
		return jwtDecoder;
	}


	/**
	 * Gets the JWT retriever.
	 *
	 * @return The JWT retriever, {@code null} if not specified.
	 */
	public ResourceRetriever getJWTRetriever() {
	
		return jwtRetriever;
	}
	
	
	/**
	 * Retrieves a JWT from the specified URL. The content type of the URL 
	 * resource is not checked.
	 *
	 * @param url The URL of the JWT. Must not be {@code null}.
	 *
	 * @return The retrieved JWT.
	 *
	 * @throws ResolveException If no JWT retriever is configured, if the
	 *                          resource couldn't be retrieved, or parsed
	 *                          to a JWT.
	 */
	private JWT retrieveRequestObject(final URL url)
		throws ResolveException {
	
		if (jwtRetriever == null) {

			throw new ResolveException("OpenID Connect request object cannot be resolved: No JWT retriever is configured");
		}

		Resource resource;

		try {
			resource = jwtRetriever.retrieveResource(url);
			
		} catch (IOException e) {

			throw new ResolveException("Couldn't retrieve OpenID Connect request object: " + e.getMessage(), e);
		}

		try {
			return JWTParser.parse(resource.getContent());
		
		} catch (java.text.ParseException e) {

			throw new ResolveException("Couldn't parse OpenID Connect request object: " +  e.getMessage(), e);
		}
	}
	
	
	/**
	 * Decodes the specified OpenID Connect request object, and if it's
	 * secured performs additional JWS signature validation and JWE
	 * decryption.
	 *
	 * @param requestObject The OpenID Connect request object to decode. 
	 *                      Must not be {@code null}.
	 *
	 * @return The extracted JWT claims of the OpenID Connect request 
	 *         object.
	 *
	 * @throws ResolveException If no JWT decoder is configured, if JWT 
	 *                          decoding, JWS validation or JWE decryption 
	 *                          failed.
	 */
	private ReadOnlyJWTClaimsSet decodeRequestObject(final JWT requestObject)
		throws ResolveException {
		
		if (jwtDecoder == null) {

			throw new ResolveException("OpenID Connect request object cannot be decoded: No JWT decoder is configured");
		}

		try {
			return jwtDecoder.decodeJWT(requestObject);
				
		} catch (JOSEException e) {
		
			throw new ResolveException("Couldn't decode OpenID Connect request object JWT: " + e.getMessage(), e);
			
		} catch (java.text.ParseException e) {

			throw new ResolveException("Couldn't parse OpenID Connect request object JWT claims: " + e.getMessage(), e);
		}
	}


	/**
	 * Reformats the specified JWT claims set to a 
	 * {@literal java.util.Map&<String,String>} instance.
	 *
	 * @param claimsSet The JWT claims set to reformat. Must not be
	 *                  {@code null}.
	 *
	 * @return The JWT claims set as an unmodifiable map of string keys / 
	 *         string values.
	 *
	 * @throws ResolveException If reformatting of the JWT claims set 
	 *                          failed.
	 */
	public static Map<String,String> reformatClaims(final ReadOnlyJWTClaimsSet claimsSet)
		throws ResolveException {

		Map<String,Object> claims = claimsSet.getAllClaims();

		// Reformat all claim values as strings
		Map<String,String> reformattedClaims = new HashMap<>();

		for (Map.Entry<String,Object> entry: claims.entrySet()) {

			Object value = entry.getValue();

			if (value instanceof String) {

				reformattedClaims.put(entry.getKey(), (String)value);

			} else if (value instanceof Boolean) {

				Boolean bool = (Boolean)value;
				reformattedClaims.put(entry.getKey(), bool.toString());

			} else if (value instanceof Number) {

				Number number = (Number)value;
				reformattedClaims.put(entry.getKey(), number.toString());

			} else if (value instanceof JSONObject) {

				JSONObject jsonObject = (JSONObject)value;
				reformattedClaims.put(entry.getKey(), jsonObject.toString());

			} else {

				throw new ResolveException("Couldn't process JWT claim \"" + entry.getKey() + "\": Unsupported type");
			}
		}

		return Collections.unmodifiableMap(reformattedClaims);
	}


	/**
	 * Resolves the specified OpenID Connect authentication request by
	 * superseding its parameters with those found in the optional OpenID 
	 * Connect request object (if any).
	 * 
	 * @param request The OpenID Connect authentication request. Must not be
	 *                {@code null}.
	 * 
	 * @return The resolved authentication request, or the original
	 *         unmodified request if no OpenID Connect request object was
	 *         specified.
	 * 
	 * @throws ResolveException If the request couldn't be resolved.
	 */
	public AuthenticationRequest resolve(final AuthenticationRequest request)
		throws ResolveException {

		if (! request.specifiesRequestObject()) {
			// Return the same request
			return request;
		}

		try {
			JWT jwt;

			if (request.getRequestURI() != null) {

				// Download request object
				URL requestURL;

				try {
					requestURL = request.getRequestURI().toURL();

				} catch (MalformedURLException e) {

					throw new ResolveException(e.getMessage(), e);
				}

				jwt = retrieveRequestObject(requestURL);
			} else {
				// Request object inlined
				jwt = request.getRequestObject();
			}

			ReadOnlyJWTClaimsSet jwtClaims = decodeRequestObject(jwt);

			Map<String, String> requestObjectParams = reformatClaims(jwtClaims);

			Map<String, String> finalParams = new HashMap<>();
			
			try {
				finalParams.putAll(request.toParameters());

			} catch (SerializeException e) {

				throw new ResolveException("Couldn't resolve final OpenID Connect authentication request: " + e.getMessage(), e);
			}

			// Merge params from request object
			finalParams.putAll(requestObjectParams);


			// Parse again
			AuthenticationRequest finalAuthRequest;

			try {
				finalAuthRequest = AuthenticationRequest.parse(request.getEndpointURI(), finalParams);

			} catch (ParseException e) {

				throw new ResolveException("Couldn't create final OpenID Connect authentication request: " + e.getMessage(), e);
			}
			
			return new AuthenticationRequest(
				finalAuthRequest.getEndpointURI(),
				finalAuthRequest.getResponseType(),
				finalAuthRequest.getScope(),
				finalAuthRequest.getClientID(),
				finalAuthRequest.getRedirectionURI(),
				finalAuthRequest.getState(),
				finalAuthRequest.getNonce(),
				finalAuthRequest.getDisplay(),
				finalAuthRequest.getPrompt(),
				finalAuthRequest.getMaxAge(),
				finalAuthRequest.getUILocales(),
				finalAuthRequest.getClaimsLocales(),
				finalAuthRequest.getIDTokenHint(),
				finalAuthRequest.getLoginHint(),
				finalAuthRequest.getACRValues(),
				finalAuthRequest.getClaims(),
				null, // request object
				null); // request URI
			
		} catch (ResolveException e) {
			
			// Repackage exception with redirection URI, state, error object
			
			ErrorObject err;
			
			if (request.getRequestURI() != null)
				err = OIDCError.INVALID_REQUEST_URI;
			else
				err = OIDCError.INVALID_REQUEST_OBJECT;
			
			throw new ResolveException(
				e.getMessage(),
				err,
				request.getClientID(),
				request.getRedirectionURI(),
				request.getState(),
				e.getCause());
		}
	}
}
