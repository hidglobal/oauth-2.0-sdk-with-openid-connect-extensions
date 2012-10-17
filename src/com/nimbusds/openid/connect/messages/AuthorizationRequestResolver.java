package com.nimbusds.openid.connect.messages;


import java.io.IOException;

import java.net.URL;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.Payload;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.claims.ClientID;

import com.nimbusds.openid.connect.util.DefaultJOSEObjectRetriever;
import com.nimbusds.openid.connect.util.JOSEObjectDecoder;
import com.nimbusds.openid.connect.util.JOSEObjectRetriever;
import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * Authorisation request resolver. Takes in a raw {@link AuthorizationRequest}
 * and if an OpenID Connect request object is present applies it to derive the
 * final authorisation request parameters, ID Token and UserInfo claims.
 *
 * <p>To process OpenID Connect request objects the resolver must be supplied 
 * with a {@link com.nimbusds.openid.connect.util.JOSEObjectRetriever retriever} 
 * for remote JOSE objects and a 
 * {@link com.nimbusds.openid.connect.util.JOSEObjectDecoder decoder} to handle 
 * their JOSE decoding and JWS validation and/or JWE decryption.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-17)
 */
public class AuthorizationRequestResolver {


	/**
	 * Retriever for JOSE objects passed as URL.
	 */
	private JOSEObjectRetriever retriever;
	
	
	/**
	 * Decoder for JOSE objects.
	 */
	private JOSEObjectDecoder decoder;
	
	
	/**
	 * Creates a new authorisation request resolver with a 
	 * {@link com.nimbusds.openid.connect.util.DefaultJOSEObjectRetriever
	 * default JOSE object retriever}.
	 *
	 * @param decoder A configured JOSE decoder and JWS validator/JWE 
	 *                decryptor for the optional OpenID Connect request
	 *                objects. Must not be {@code null}.
	 */
	public AuthorizationRequestResolver(final JOSEObjectDecoder decoder) {
	
		this(new DefaultJOSEObjectRetriever(), decoder);
	}
	
	
	/**
	 * Creates a new authorisation request resolver.
	 *
	 * @param retriever A configured retriever for optional OpenID Connect
	 *                  request objects passed by URI reference. Must not be
	 *                  {@code null}.
	 * @param decoder   A configured JOSE decoder and JWS validator/JWE 
	 *                  decryptor for the optional OpenID Connect request
	 *                  objects. Must not be {@code null}.
	 */
	public AuthorizationRequestResolver(final JOSEObjectRetriever retriever,
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
	 * Downloads an OpenID Connect request object from the specified URL.
	 *
	 * @param url The URL of the OpenID Connect request object. Must not be
	 *            {@code null}.
	 *
	 * @return The downloaded JOSE-encoded request object.
	 *
	 * @throws ResolveException If the request object couldn't be downloaded
	 *                          or couldn't be parsed to a JOSE-encoded 
	 *                          object.
	 */
	private JOSEObject downloadRequestObject(final URL url)
		throws ResolveException {
	
		try {
			return retriever.downloadJOSEObject(url);
			
		} catch (IOException e) {

			throw new ResolveException("Couldn't download OpenID Connect request object: " + e.getMessage(), e);

		} catch (ParseException e) {

			throw new ResolveException("Couldn't parse downloaded OpenID Connect request object: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * JOSE decodes and JWS validates and/or JWE decrypts the specified
	 * OpenID Connect request object.
	 *
	 * @param joseObject The JOSE object to decode. Must not be 
	 *                   {@code null}.
	 *
	 * @return The JSON object representing the OpenID Connect request 
	 *         object.
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
		
			throw new ResolveException("Couldn't decode/verify JOSE encoded OpenID Connect request object: " + e.getMessage(), e);
		}
		
		JSONObject jsonObject = payload.toJSONObject();
		
		if (jsonObject == null)
			throw new ResolveException("JOSE object payload not a valid JSON object");
		
		return jsonObject;
	}
	
	
	/**
	 * Resolves the response type set.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved response type set.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static ResponseTypeSet resolveResponseTypeSet(final AuthorizationRequest request, 
	                                                      final JSONObject requestObject)
		throws ResolveException {
	
		ResponseTypeSet rts = request.getResponseTypeSet();
		
		if (JSONObjectUtils.containsKey(requestObject, "response_type")) {
		
			ResponseTypeSet rtsCopy = null;
			
			try {
				String value = JSONObjectUtils.getString(requestObject, "response_type");
			
				rtsCopy = ResponseTypeSet.parse(value);
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"response_type\" parameter in OpenID Connect request object: " + e.getMessage(), e);
			}
			
			if (! rts.containsAll(rtsCopy))
				throw new ResolveException("Mismatched \"response_type\" parameter in OpenID Connect request object");
		}
		
		return rts;
	}
	
	
	/**
	 * Resolves the UserInfo scope.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved UserInfo scope.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static Scope resolveScope(final AuthorizationRequest request,
	                                  final JSONObject requestObject)
		throws ResolveException {
		
		Scope scope = request.getScope();
		
		if (JSONObjectUtils.containsKey(requestObject, "scope")) {
		
			Scope scopeCopy = null;
			
			try {
				String value = JSONObjectUtils.getString(requestObject, "scope");
			
				scopeCopy = Scope.parseStrict(value);
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"scope\" parameter in OpenID Connect request object: " + e.getMessage(), e);
			}
			
			if (! scope.containsAll(scopeCopy))
				throw new ResolveException("Mismatched \"scope\" parameter in OpenID Connect request object");
		}
		
		return scope;
	}
	
	
	/**
	 * Resolves the client ID.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved client ID.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static ClientID resolveClientID(final AuthorizationRequest request,
	                                        final JSONObject requestObject)
		throws ResolveException {
		
		ClientID clientID = request.getClientID();
		
		if (JSONObjectUtils.containsKey(requestObject, "client_id")) {
		
			ClientID clientIDCopy = new ClientID();
			
			try {
				String value = JSONObjectUtils.getString(requestObject, "client_id");
			
				clientIDCopy.setClaimValue(value);
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"client_id\" parameter in OpenID Connect request object: " + e.getMessage(), e);
			}
			
			if (! clientID.equals(clientIDCopy))
				throw new ResolveException("Mismatched \"client_id\" parameter in OpenID Connect request object");
		}
		
		return clientID;
	}
	
	
	/**
	 * Resolves the redirect URI.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved redirect URI.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static URL resolveRedirectURI(final AuthorizationRequest request,
	                                      final JSONObject requestObject)
		throws ResolveException {
		
		URL url = request.getRedirectURI();
		
		if (JSONObjectUtils.containsKey(requestObject, "redirect_uri")) {
		
			URL urlCopy = null;
			
			try {
				urlCopy = JSONObjectUtils.getURL(requestObject, "redirect_uri");
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"redirect_uri\" parameter in OpenID Connect request object: " + e.getMessage(), e);
			}
			
			if (! url.equals(urlCopy))
				throw new ResolveException("Mismatched \"redirect_uri\" parameter in OpenID Connect request object");
		}
		
		return url;
	}
	
	
	/**
	 * Resolves the nonce parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved nonce, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static Nonce resolveNonce(final AuthorizationRequest request,
	                                  final JSONObject requestObject)
		throws ResolveException {
		
		Nonce nonce = request.getNonce();
		
		if (JSONObjectUtils.containsKey(requestObject, "nonce")) {
		
			Nonce nonceCopy = null;
			
			try {
				nonceCopy = new Nonce(JSONObjectUtils.getString(requestObject, "nonce"));
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"nonce\" parameter in OpenID Connect request object: " + e.getMessage(), e);
			}
			
			if (nonce == null)
				nonce = nonceCopy;
			
			else if (! nonce.equals(nonceCopy))
				throw new ResolveException("Mismatched \"nonce\" parameter in OpenID Connect request object");
		}
		
		return nonce;
	}
	
	
	/**
	 * Resolves the state parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved state, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static State resolveState(final AuthorizationRequest request,
	                                  final JSONObject requestObject)
		throws ResolveException {
		
		State state = request.getState();
		
		if (JSONObjectUtils.containsKey(requestObject, "state")) {
		
			State stateCopy = null;
			
			try {
				stateCopy = new State(JSONObjectUtils.getString(requestObject, "state"));
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"state\" parameter in OpenID Connect request object: " + e.getMessage(), e);
			}
			
			if (state == null)
				state = stateCopy;
			
			else if (! state.equals(stateCopy))
				throw new ResolveException("Mismatched \"state\" parameter in OpenID Connect request object");
		}
		
		return state;
	}
	
	
	/**
	 * Resolves the display parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved display, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static Display resolveDisplay(final AuthorizationRequest request,
	                                      final JSONObject requestObject)
		throws ResolveException {
		
		Display display = request.getDisplay();
	        	       
		if (JSONObjectUtils.containsKey(requestObject, "display")) {

		       Display displayCopy = null;

		       try {
			       display = Display.parse(JSONObjectUtils.getString(requestObject, "display"));

		       } catch (ParseException e) {

			       throw new ResolveException("Invalid \"display\" parameter in OpenID Connect request object: " + e.getMessage(), e);
		       }

		       if (display == null)
			       display = displayCopy;

		       else if (! display.equals(displayCopy))
			       throw new ResolveException("Mismatched \"display\" parameter in OpenID Connect request object");
		}

		return display;
	}
	
	
	/**
	 * Resolves the prompt parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved prompt, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static Prompt resolvePrompt(final AuthorizationRequest request,
	                                    final JSONObject requestObject)
		throws ResolveException {
		
		Prompt prompt = request.getPrompt();
	        	       
		if (JSONObjectUtils.containsKey(requestObject, "prompt")) {

		       Prompt promptCopy = null;

		       try {
			       prompt = Prompt.parse(JSONObjectUtils.getString(requestObject, "prompt"));

		       } catch (ParseException e) {

			       throw new ResolveException("Invalid \"prompt\" parameter in OpenID Connect request object: " + e.getMessage(), e);
		       }

		       if (prompt == null)
			       prompt = promptCopy;

		       else if (! prompt.equals(promptCopy))
			       throw new ResolveException("Mismatched \"prompt\" parameter in OpenID Connect request object");
		}

		return prompt;
	}
	
	
	/**
	 * Resolves the ID Token hint parameter.
	 *
	 * @param request       The original authorisation request. Must not be 
	 *                      {@code null}.
	 * @param requestObject The decoded OpenID Connect request object, 
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved ID Token hint, {@code null} if not specified.
	 *
	 * @throws ResolveException If the OpenID Connect request object 
	 *                          contains an invalid instance or mismatching
	 *                          copy of the parameter to resolve.
	 */
	private static JWT resolveIDTokenHint(final AuthorizationRequest request,
	                                      final JSONObject requestObject)
		throws ResolveException {
		
		JWT idTokenHint = request.getIDTokenHint();
	        	       
		if (JSONObjectUtils.containsKey(requestObject, "id_token_hint")) {

			JWT idTokenHintCopy = null;

			try {
			       idTokenHintCopy = JWTParser.parse(JSONObjectUtils.getString(requestObject, "id_token_hint"));

			} catch (ParseException e) {

			       throw new ResolveException("Invalid \"id_token_hint\" parameter in OpenID Connect request object: " + e.getMessage(), e);

			} catch (java.text.ParseException e) {

			       throw new ResolveException("Invalid \"id_token_hint\" parameter in OpenID Connect request object: " + e.getMessage(), e);
			}

			if (idTokenHint == null)
			       idTokenHint = idTokenHintCopy;

			else if (! idTokenHint.equals(idTokenHintCopy))
			       throw new ResolveException("Mismatched \"id_token_hint\" parameter in OpenID Connect request object");
		}

		return idTokenHint;
	}
	
	
	/**
	 * Resolves an authorisation request.
	 * 
	 * @param request The authorisation request to resolve. Must not be 
	 *                {@code null}.
	 *
	 * @return The resolved requested authorisation parameters, ID Token and 
	 *         UserInfo claims.
	 *
	 * @throws ResolveException If the authorisation request couldn't be 
	 *                          resolved due to an invalid OpenID Connect
	 *                          request object.
	 */
	public ResolvedAuthorizationRequest resolve(final AuthorizationRequest request)
		throws ResolveException {
	
		JSONObject requestObject = null;
		
		if (request.hasRequestObject()) {
		
			// Fetch + decode the request object
		
			JOSEObject encodedRequestObject = null;
		
			if (request.getRequestObjectURI() != null) {
			
				encodedRequestObject = downloadRequestObject(request.getRequestObjectURI());
			}
			else {
			
				encodedRequestObject = request.getRequestObject();
			}
			
			requestObject = decodeRequestObject(encodedRequestObject);
		}
		
		
		// Get resolved request parameters
		ResponseTypeSet rts = resolveResponseTypeSet(request, requestObject);
		Scope scope = resolveScope(request, requestObject);
		ClientID clientID = resolveClientID(request, requestObject);
		URL redirectURI = resolveRedirectURI(request, requestObject);
		Nonce nonce = resolveNonce(request, requestObject);
		State state = resolveState(request, requestObject);
		Display display = resolveDisplay(request, requestObject);
		Prompt prompt = resolvePrompt(request, requestObject);
		JWT idTokenHint = resolveIDTokenHint(request, requestObject);
		
		
		// Resolve requested ID Token claims
		JSONObject idTokenObject = null;
		
		if (JSONObjectUtils.containsKey(requestObject, "id_token")) {
		
			try {
				idTokenObject = JSONObjectUtils.getJSONObject(requestObject, "id_token");
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"id_token\" member in OpenID Connect request object: " + e.getMessage(), e);
			}
		}
		
		IDTokenClaimsRequest idTokenClaimsRequest = new IDTokenClaimsRequest(rts, idTokenObject);
		
		
		
		// Resolve requested UserInfo claims
		JSONObject userInfoObject = null;
		
		if (JSONObjectUtils.containsKey(requestObject, "userinfo")) {
		
			try {
				userInfoObject = JSONObjectUtils.getJSONObject(requestObject, "userinfo");
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"userinfo\" member in OpenID Connect request object: " + e.getMessage(), e);
			}
		}
		
		UserInfoClaimsRequest userInfoClaimsRequest = new UserInfoClaimsRequest(scope, userInfoObject);
		
		
		return new ResolvedAuthorizationRequest(rts, clientID, redirectURI,
		                                        nonce, state, display, prompt, idTokenHint,
							idTokenClaimsRequest, userInfoClaimsRequest);
	}
}
