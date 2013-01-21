package com.nimbusds.openid.connect.sdk;


import java.io.IOException;

import java.net.URL;

import net.jcip.annotations.ThreadSafe;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.Payload;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseTypeSet;
import com.nimbusds.oauth2.sdk.Scope;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.util.DefaultJOSEObjectRetriever;
import com.nimbusds.openid.connect.sdk.util.JOSEObjectDecoder;
import com.nimbusds.openid.connect.sdk.util.JOSEObjectRetriever;



/**
 * OpenID Connect authorisation request resolver. Takes in a raw 
 * {@link OIDCAuthorizationRequest} and if an OpenID request object is present
 * applies it to derive the final authorisation request parameters, ID Token 
 * and UserInfo claims.
 *
 * <p>To process OpenID request objects the resolver must be supplied with a
 * {@link com.nimbusds.openid.connect.sdk.util.JOSEObjectRetriever retriever} 
 * for remote JOSE objects and a 
 * {@link com.nimbusds.openid.connect.sdk.util.JOSEObjectDecoder decoder} to 
 * handle their JOSE decoding and JWS validation and/or JWE decryption.
 *
 * <p>This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
 */
@ThreadSafe
public class OIDCAuthorizationRequestResolver {


	/**
	 * Retriever for JOSE objects passed as URL.
	 */
	private final JOSEObjectRetriever retriever;
	
	
	/**
	 * Decoder for JOSE objects.
	 */
	private final JOSEObjectDecoder decoder;
	
	
	/**
	 * Creates a new OpenID Connect authorisation request resolver with a 
	 * {@link com.nimbusds.openid.connect.sdk.util.DefaultJOSEObjectRetriever
	 * default JOSE object retriever}.
	 *
	 * @param decoder A configured JOSE decoder and JWS validator/JWE 
	 *                decryptor for the optional OpenID request objects. 
	 *                Must not be {@code null}.
	 */
	public OIDCAuthorizationRequestResolver(final JOSEObjectDecoder decoder) {
	
		this(new DefaultJOSEObjectRetriever(), decoder);
	}
	
	
	/**
	 * Creates a new OpenID Connect authorisation request resolver.
	 *
	 * @param retriever A configured retriever for optional OpenID request
	 *                  objects passed by URI reference. Must not be
	 *                  {@code null}.
	 * @param decoder   A configured JOSE decoder and JWS validator/JWE 
	 *                  decryptor for the optional OpenID request objects.
	 *                  Must not be {@code null}.
	 */
	public OIDCAuthorizationRequestResolver(final JOSEObjectRetriever retriever,
	                                        final JOSEObjectDecoder decoder) {
		
		this.retriever = retriever;
		this.decoder = decoder;
	}
	
	
	/**
	 * Gets the configured JOSE object retriever.
	 *
	 * @return The JOSE object retriever.
	 */
	public JOSEObjectRetriever getJOSEObjectRetriever() {
	
		return retriever;
	}
	
	
	/**
	 * Gets the configured JOSE object decoder.
	 *
	 * @return The JOSE object decoder.
	 */
	public JOSEObjectDecoder getJOSEObjectDecoder() {
	
		return decoder;
	}
	
	
	/**
	 * Downloads an OpenID request object from the specified URL.
	 *
	 * @param url The URL of the OpenID request object. Must not be
	 *            {@code null}.
	 *
	 * @return The downloaded JOSE-encoded request object.
	 *
	 * @throws ResolveException If the request object couldn't be 
	 *                          downloaded or parsed to a JOSE-encoded 
	 *                          object.
	 */
	private JOSEObject downloadRequestObject(final URL url)
		throws ResolveException {
	
		try {
			return retriever.downloadJOSEObject(url);
			
		} catch (IOException e) {

			throw new ResolveException("Couldn't download OpenID request object: " + 
				                   e.getMessage(), e);

		} catch (ParseException e) {

			throw new ResolveException("Couldn't parse downloaded OpenID request object: " + 
				                   e.getMessage(), e);
		}
	}
	
	
	/**
	 * JOSE-decodes and JWS-validates and / or JWE-decrypts the specified
	 * OpenID request object.
	 *
	 * @param joseObject The JOSE object to decode. Must not be 
	 *                   {@code null}.
	 *
	 * @return The JSON object representing the OpenID request object.
	 *
	 * @throws ResolveException If JOSE decoding, JWS validation or JWE
	 *                          decryption failed.
	 */
	private JSONObject decodeRequestObject(final JOSEObject joseObject)
		throws ResolveException {
		
		Payload payload = null;
		
		try {
			payload = decoder.decodeJOSEObject(joseObject);
				
		} catch (JOSEException e) {
		
			throw new ResolveException("Couldn't decode/verify JOSE encoded OpenID request object: " + 
				                   e.getMessage(), e);
		}
		
		JSONObject jsonObject = payload.toJSONObject();
		
		if (jsonObject == null)
			throw new ResolveException("JOSE object payload not a valid JSON object");
		
		return jsonObject;
	}
	
	
	/**
	 * Resolves the response type set.
	 *
	 * @param request       The original OpenID Connect authorisation 
	 *                      request. Must not be {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                       if not specified.
	 *
	 * @return The resolved response type set.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static ResponseTypeSet resolveResponseTypeSet(final OIDCAuthorizationRequest request, 
	                                                      final JSONObject requestObject)
		throws ResolveException {
	
		ResponseTypeSet rts = request.getResponseTypeSet();
		
		if (JSONObjectUtils.containsKey(requestObject, "response_type")) {
		
			ResponseTypeSet rtsCopy = null;
			
			try {
				String value = JSONObjectUtils.getString(requestObject, "response_type");
			
				rtsCopy = ResponseTypeSet.parse(value);
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"response_type\" parameter in OpenID request object: " + 
					                   e.getMessage(), e);
			}
			
			if (! rts.containsAll(rtsCopy))
				throw new ResolveException("Mismatched \"response_type\" parameter in OpenID request object");
		}
		
		return rts;
	}
	
	
	/**
	 * Resolves the UserInfo scope.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved UserInfo scope.
	 *
	 * @throws ResolveException If the OpenID request object contains an
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static Scope resolveScope(final OIDCAuthorizationRequest request,
	                                  final JSONObject requestObject)
		throws ResolveException {
		
		Scope scope = request.getScope();
		
		if (JSONObjectUtils.containsKey(requestObject, "scope")) {
		
			Scope scopeCopy = null;
			
			try {
				String value = JSONObjectUtils.getString(requestObject, "scope");
			
				scopeCopy = Scope.parse(value);
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"scope\" parameter in OpenID request object: " + 
					                   e.getMessage(), e);
			}
			
			if (! scope.containsAll(scopeCopy))
				throw new ResolveException("Mismatched \"scope\" parameter in OpenID request object");
		}
		
		return scope;
	}
	
	
	/**
	 * Resolves the client ID.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved client ID.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static ClientID resolveClientID(final OIDCAuthorizationRequest request,
	                                        final JSONObject requestObject)
		throws ResolveException {
		
		ClientID clientID = request.getClientID();
		
		if (JSONObjectUtils.containsKey(requestObject, "client_id")) {
		
			ClientID clientIDCopy = null;
			
			try {
				clientIDCopy = new ClientID(JSONObjectUtils.getString(requestObject, "client_id"));
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"client_id\" parameter in OpenID request object: " + 
					                   e.getMessage(), e);
			}
			
			if (! clientID.equals(clientIDCopy))
				throw new ResolveException("Mismatched \"client_id\" parameter in OpenID request object");
		}
		
		return clientID;
	}
	
	
	/**
	 * Resolves the redirection URI.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved redirect URI.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static URL resolveRedirectURI(final OIDCAuthorizationRequest request,
	                                      final JSONObject requestObject)
		throws ResolveException {
		
		URL url = request.getRedirectURI();
		
		if (JSONObjectUtils.containsKey(requestObject, "redirect_uri")) {
		
			URL urlCopy = null;
			
			try {
				urlCopy = JSONObjectUtils.getURL(requestObject, "redirect_uri");
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"redirect_uri\" parameter in OpenID request object: " + 
					                   e.getMessage(), e);
			}
			
			if (! url.equals(urlCopy))
				throw new ResolveException("Mismatched \"redirect_uri\" parameter in OpenID request object");
		}
		
		return url;
	}
	
	
	/**
	 * Resolves the nonce parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved nonce, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static Nonce resolveNonce(final OIDCAuthorizationRequest request,
	                                  final JSONObject requestObject)
		throws ResolveException {
		
		Nonce nonce = request.getNonce();
		
		if (JSONObjectUtils.containsKey(requestObject, "nonce")) {
		
			Nonce nonceCopy = null;
			
			try {
				nonceCopy = new Nonce(JSONObjectUtils.getString(requestObject, "nonce"));
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"nonce\" parameter in OpenID request object: " + 
					                   e.getMessage(), e);
			}
			
			if (nonce == null)
				nonce = nonceCopy;
			
			else if (! nonce.equals(nonceCopy))
				throw new ResolveException("Mismatched \"nonce\" parameter in OpenID request object");
		}
		
		return nonce;
	}
	
	
	/**
	 * Resolves the state parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved state, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static State resolveState(final OIDCAuthorizationRequest request,
	                                  final JSONObject requestObject)
		throws ResolveException {
		
		State state = request.getState();
		
		if (JSONObjectUtils.containsKey(requestObject, "state")) {
		
			State stateCopy = null;
			
			try {
				stateCopy = new State(JSONObjectUtils.getString(requestObject, "state"));
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"state\" parameter in OpenID request object: " + 
					                   e.getMessage(), e);
			}
			
			if (state == null)
				state = stateCopy;
			
			else if (! state.equals(stateCopy))
				throw new ResolveException("Mismatched \"state\" parameter in OpenID request object");
		}
		
		return state;
	}
	
	
	/**
	 * Resolves the display parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved display (the default value if not specified).
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static Display resolveDisplay(final OIDCAuthorizationRequest request,
	                                      final JSONObject requestObject)
		throws ResolveException {
		
		Display display = request.getDisplay();
	        	       
		if (JSONObjectUtils.containsKey(requestObject, "display")) {

		       Display displayCopy = null;

		       try {
			       displayCopy = Display.parse(JSONObjectUtils.getString(requestObject, "display"));

		       } catch (ParseException e) {

			       throw new ResolveException("Invalid \"display\" parameter in OpenID request object: " + 
			       	                          e.getMessage(), e);
		       }

		       if (display == null)
			       display = displayCopy;

		       else if (! display.equals(displayCopy))
			       throw new ResolveException("Mismatched \"display\" parameter in OpenID request object");
		}

		if (display == null)
			display = Display.getDefault();

		return display;
	}
	
	
	/**
	 * Resolves the prompt parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved prompt, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static Prompt resolvePrompt(final OIDCAuthorizationRequest request,
	                                    final JSONObject requestObject)
		throws ResolveException {
		
		Prompt prompt = request.getPrompt();
	        	       
		if (JSONObjectUtils.containsKey(requestObject, "prompt")) {

		       Prompt promptCopy = null;

		       try {
			       promptCopy = Prompt.parse(JSONObjectUtils.getString(requestObject, "prompt"));

		       } catch (ParseException e) {

			       throw new ResolveException("Invalid \"prompt\" parameter in OpenID request object: " + 
			       	                          e.getMessage(), e);
		       }

		       if (prompt == null)
			       prompt = promptCopy;

		       else if (! prompt.equals(promptCopy))
			       throw new ResolveException("Mismatched \"prompt\" parameter in OpenID request object");
		}

		return prompt;
	}
	
	
	/**
	 * Resolves the ID Token hint parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved ID Token hint, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static JWT resolveIDTokenHint(final OIDCAuthorizationRequest request,
	                                      final JSONObject requestObject)
		throws ResolveException {
		
		JWT idTokenHint = request.getIDTokenHint();
	        	       
		if (JSONObjectUtils.containsKey(requestObject, "id_token_hint")) {

			JWT idTokenHintCopy = null;

			try {
			       idTokenHintCopy = JWTParser.parse(JSONObjectUtils.getString(requestObject, "id_token_hint"));

			} catch (ParseException e) {

			       throw new ResolveException("Invalid \"id_token_hint\" parameter in OpenID request object: " + 
			       	                          e.getMessage(), e);

			} catch (java.text.ParseException e) {

			       throw new ResolveException("Invalid \"id_token_hint\" parameter in OpenID request object: " + 
			       	                          e.getMessage(), e);
			}

			if (idTokenHint == null)
			       idTokenHint = idTokenHintCopy;

			else if (! idTokenHint.equals(idTokenHintCopy))
			       throw new ResolveException("Mismatched \"id_token_hint\" parameter in OpenID request object");
		}

		return idTokenHint;
	}


	/**
	 * Resolves the login hint parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved login hint.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static String resolveLoginHint(final OIDCAuthorizationRequest request,
	                                       final JSONObject requestObject)
		throws ResolveException {
		
		String loginHint = request.getLoginHint();
	        	       
		if (JSONObjectUtils.containsKey(requestObject, "login_hint")) {

		       String loginHintCopy = null;

		       try {
			       loginHintCopy = JSONObjectUtils.getString(requestObject, "login_hint");

		       } catch (ParseException e) {

			       throw new ResolveException("Invalid \"login_hint\" parameter in OpenID request object: " + 
			       	                          e.getMessage(), e);
		       }

		       if (loginHint == null)
			       loginHint = loginHintCopy;

		       else if (! loginHint.equals(loginHintCopy))
			       throw new ResolveException("Mismatched \"login_hint\" parameter in OpenID request object");
		}

		return loginHint;
	}


	/**
	 * Resolves the ID token claims request.
	 *
	 * @param rts           The resolved response type set. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 * @param redirectURI   The redirection URI, must not be {@code null}.
	 * @param state         Optional state parameter, {@code null} if not
	 *                      specified.
	 *
	 * @return The resolved ID token claims request, {@code null} if an
	 *         ID token is not requested.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static IDTokenClaimsRequest resolveIDTokenClaimsRequest(final ResponseTypeSet rts,
		                                                        final JSONObject requestObject,
		                                                        final URL redirectURI,
		                                                        final State state)
		throws ResolveException {

		// ID token requested?
		if (! rts.contains(ResponseType.CODE) && ! rts.contains(OIDCResponseType.ID_TOKEN))
			return null;

		// Resolve requested ID token claims
		JSONObject idTokenObject = null;
		
		if (JSONObjectUtils.containsKey(requestObject, "id_token")) {
		
			try {
				idTokenObject = JSONObjectUtils.getJSONObject(requestObject, "id_token");
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"id_token\" member in OpenID request object: " + 
					                   e.getMessage(), e);
			}
		}
		
		return new IDTokenClaimsRequest(rts, idTokenObject, redirectURI, state);
	}


	/**
	 * Resolves the UserInfo claims request.
	 *
	 * @param rts           The resolved response type set. Must not be 
	 *                      {@code null}.
	 * @param scope         The resolved UserInfo request scope. Must not 
	 *                      be {@code null}.
	 * @param requestObject The decoded OpenID request object, {@code null}
	 *                      if not specified.
	 *
	 * @return The resolved UserInfo claims request, {@code null} if a
	 *         UserInfo response is not requested.
	 *
	 * @throws ResolveException If the OpenID request object contains an 
	 *                          invalid instance or mismatching copy of the
	 *                          parameter to resolve.
	 */
	private static UserInfoClaimsRequest resolveUserInfoClaimsRequest(final ResponseTypeSet rts,
		                                                          final Scope scope,
		                                                          final JSONObject requestObject)
		throws ResolveException {

		// UserInfo requested?
		if (! rts.contains(ResponseType.CODE) && ! rts.contains(ResponseType.TOKEN))
			return null;

		// Resolve requested UserInfo claims
		JSONObject userInfoObject = null;
		
		if (JSONObjectUtils.containsKey(requestObject, "userinfo")) {
		
			try {
				userInfoObject = JSONObjectUtils.getJSONObject(requestObject, "userinfo");
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"userinfo\" member in OpenID request object: " + 
					                   e.getMessage(), e);
			}
		}
		
		return new UserInfoClaimsRequest(scope, userInfoObject);
	}
	
	
	/**
	 * Resolves an OpenID Connect authorisation request.
	 * 
	 * @param request The OpenID Connect authorisation request to resolve. 
	 *                Must not be {@code null}.
	 *
	 * @return The resolved requested authorisation parameters, ID Token 
	 *         and UserInfo claims.
	 *
	 * @throws ResolveException If the authorisation request couldn't be 
	 *                          resolved due to an invalid OpenID request
	 *                          object.
	 */
	public ResolvedOIDCAuthorizationRequest resolve(final OIDCAuthorizationRequest request)
		throws ResolveException {
	
		// Need redirectURI + state params to create exceptions with 
		// HTTP 302 redirect
		URL redirectURI = request.getRedirectURI();
		State state = request.getState();


		JSONObject requestObject = null;
		
		// Do we have an OpenID request object?
		if (request.hasRequestObject()) {
		
			JOSEObject encodedRequestObject = null;
		
			if (request.getRequestObjectURI() != null) {
			
				// The request object must be downloaded from URI
				try {
					encodedRequestObject = downloadRequestObject(request.getRequestObjectURI());

				} catch (ResolveException e) {

					throw new ResolveException(e.getMessage(), OIDCError.INVALID_REQUEST_URI, 
						                   redirectURI, state, e);
				}
			}
			else {
				// The request object is inlined
				encodedRequestObject = request.getRequestObject();
			}
			
			try {
				requestObject = decodeRequestObject(encodedRequestObject);

			} catch (ResolveException e) {

				throw new ResolveException(e.getMessage(), OIDCError.INVALID_OPENID_REQUEST_OBJECT,
					                   redirectURI, state, e);
			}
		}
		
		
		// Resolve request parameters
		ResponseTypeSet rts = null;
		Scope scope = null;
		ClientID clientID = null;
		Nonce nonce = null;
		Display display = null;
		Prompt prompt = null;
		JWT idTokenHint = null;
		String loginHint;
		IDTokenClaimsRequest idTokenClaimsRequest = null;
		UserInfoClaimsRequest userInfoClaimsRequest = null;

		try {
			redirectURI = resolveRedirectURI(request, requestObject);
			state = resolveState(request, requestObject);
			rts = resolveResponseTypeSet(request, requestObject);
			scope = resolveScope(request, requestObject);
			clientID = resolveClientID(request, requestObject);
			nonce = resolveNonce(request, requestObject);
			display = resolveDisplay(request, requestObject);
			prompt = resolvePrompt(request, requestObject);
			idTokenHint = resolveIDTokenHint(request, requestObject);
			loginHint = resolveLoginHint(request, requestObject);

			// Resolve requested ID Token claims, may be null
			idTokenClaimsRequest = resolveIDTokenClaimsRequest(rts, requestObject, redirectURI, state);

			// Resolve requested UserInfo claims, may be null
			userInfoClaimsRequest = resolveUserInfoClaimsRequest(rts, scope, requestObject);

		} catch (ResolveException e) {

			throw new ResolveException(e.getMessage(), OAuth2Error.INVALID_REQUEST,
				                   redirectURI, state, e);
		}

		
		return new ResolvedOIDCAuthorizationRequest(rts, clientID, redirectURI,
		                                            nonce, state, display, prompt, idTokenHint, loginHint,
							    idTokenClaimsRequest, userInfoClaimsRequest);
	}
}
