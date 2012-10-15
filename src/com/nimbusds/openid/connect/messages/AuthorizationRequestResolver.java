package com.nimbusds.openid.connect.messages;


import java.io.IOException;

import java.net.URL;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.claims.ClientID;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * Authorisation request resolver.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-15)
 */
public class AuthorizationRequestResolver {


	/**
	 * Retriever for OpenID Connect request objects passed as URL.
	 */
	private RequestObjectRetriever retriever;
	
	
	/**
	 * Decoder for JOSE-encoded OpenID Connect request objects.
	 */
	private RequestObjectDecoder decoder;
	
	
	/**
	 * Creates a new authorisation request resolver with a 
	 * {@link DefaultRequestObjectRetriever default OpenID Connect request 
	 * object retriever}.
	 *
	 * @param decoder
	 */
	public AuthorizationRequestResolver(final RequestObjectDecoder decoder) {
	
		this(new DefaultRequestObjectRetriever(), decoder);
	}
	
	
	/**
	 * Creates a new authorisation request resolver.
	 *
	 * @param retriever
	 * @param decoder
	 */
	public AuthorizationRequestResolver(final RequestObjectRetriever retriever,
	                                    final RequestObjectDecoder decoder) {
					     
		this.retriever = retriever;
		
		this.decoder = decoder;
	}
	
	
	public RequestObjectRetriever getRequestObjectRetriever() {
	
		return retriever;
	}
	
	
	public RequestObjectDecoder getRequestObjectDecoder() {
	
		return decoder;
	}
	
	
	/**
	 * Downloads an OpenID Connect request object at the specified URL.
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
			return retriever.downloadRequestObject(url);
			
		} catch (IOException e) {

			throw new ResolveException("Couldn't download OpenID Connect request object: " + e.getMessage(), e);

		} catch (ParseException e) {

			throw new ResolveException("Couldn't parse downloaded OpenID Connect request object: " + e.getMessage(), e);
		}
	}
	
	
	private JSONObject decodeRequestObject(final JOSEObject joseObject)
		throws ResolveException {
		
		try {
			return decoder.decodeRequestObject(joseObject);
				
		} catch (JOSEException e) {
		
			throw new ResolveException("Couldn't decode/verify OpenID Connect request object: " + e.getMessage(), e);
		}
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
		
		if (requestObject != null && requestObject.containsKey("response_type")) {
		
			ResponseTypeSet rtsCopy = null;
			
			try {
				String value = JSONObjectUtils.getString(requestObject, "response_type");
			
				rtsCopy = ResponseTypeSet.parse(value);
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"response_type\" parameter in request object: " + e.getMessage(), e);
			}
			
			if (! rts.containsAll(rtsCopy))
				throw new ResolveException("Mismatched \"response_type\" parameter in request object");
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
		
		if (requestObject != null && requestObject.containsKey("scope")) {
		
			Scope scopeCopy = null;
			
			try {
				String value = JSONObjectUtils.getString(requestObject, "scope");
			
				scopeCopy = Scope.parseStrict(value);
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"scope\" parameter in request object: " + e.getMessage(), e);
			}
			
			if (! scope.containsAll(scopeCopy))
				throw new ResolveException("Mismatched \"scope\" parameter in request object");
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
		
		if (requestObject != null && requestObject.containsKey("client_id")) {
		
			ClientID clientIDCopy = new ClientID();
			
			try {
				String value = JSONObjectUtils.getString(requestObject, "client_id");
			
				clientIDCopy.setClaimValue(value);
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"client_id\" parameter in request object: " + e.getMessage(), e);
			}
			
			if (! clientID.equals(clientIDCopy))
				throw new ResolveException("Mismatched \"client_id\" parameter in request object");
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
		
		if (requestObject != null && requestObject.containsKey("redirect_uri")) {
		
			URL urlCopy = null;
			
			try {
				urlCopy = JSONObjectUtils.getURL(requestObject, "redirect_uri");
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"redirect_uri\" parameter in request object: " + e.getMessage(), e);
			}
			
			if (! url.equals(urlCopy))
				throw new ResolveException("Mismatched \"redirect_uri\" parameter in request object");
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
		
		if (requestObject != null && requestObject.containsKey("nonce")) {
		
			Nonce nonceCopy = null;
			
			try {
				nonceCopy = new Nonce(JSONObjectUtils.getString(requestObject, "nonce"));
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"nonce\" parameter in request object: " + e.getMessage(), e);
			}
			
			if (nonce == null)
				nonce = nonceCopy;
			
			else if (! nonce.equals(nonceCopy))
				throw new ResolveException("Mismatched \"nonce\" parameter in request object");
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
		
		if (requestObject != null && requestObject.containsKey("state")) {
		
			State stateCopy = null;
			
			try {
				stateCopy = new State(JSONObjectUtils.getString(requestObject, "state"));
				
			} catch (ParseException e) {
			
				throw new ResolveException("Invalid \"state\" parameter in request object: " + e.getMessage(), e);
			}
			
			if (state == null)
				state = stateCopy;
			
			else if (! state.equals(stateCopy))
				throw new ResolveException("Mismatched \"state\" parameter in request object");
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
	        	       
		if (requestObject != null && requestObject.containsKey("display")) {

		       Display displayCopy = null;

		       try {
			       display = Display.parse(JSONObjectUtils.getString(requestObject, "display"));

		       } catch (ParseException e) {

			       throw new ResolveException("Invalid \"display\" parameter in request object: " + e.getMessage(), e);
		       }

		       if (display == null)
			       display = displayCopy;

		       else if (! display.equals(displayCopy))
			       throw new ResolveException("Mismatched \"display\" parameter in request object");
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
	        	       
		if (requestObject != null && requestObject.containsKey("prompt")) {

		       Prompt promptCopy = null;

		       try {
			       prompt = Prompt.parse(JSONObjectUtils.getString(requestObject, "prompt"));

		       } catch (ParseException e) {

			       throw new ResolveException("Invalid \"prompt\" parameter in request object: " + e.getMessage(), e);
		       }

		       if (prompt == null)
			       prompt = promptCopy;

		       else if (! prompt.equals(promptCopy))
			       throw new ResolveException("Mismatched \"prompt\" parameter in request object");
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
	        	       
		if (requestObject != null && requestObject.containsKey("id_token_hint")) {

			JWT idTokenHintCopy = null;

			try {
			       idTokenHintCopy = JWTParser.parse(JSONObjectUtils.getString(requestObject, "id_token_hint"));

			} catch (ParseException e) {

			       throw new ResolveException("Invalid \"id_token_hint\" parameter in request object: " + e.getMessage(), e);

			} catch (java.text.ParseException e) {

			       throw new ResolveException("Invalid \"id_token_hint\" parameter in request object: " + e.getMessage(), e);
			}

			if (idTokenHint == null)
			       idTokenHint = idTokenHintCopy;

			else if (! idTokenHint.equals(idTokenHintCopy))
			       throw new ResolveException("Mismatched \"id_token_hint\" parameter in request object");
		}

		return idTokenHint;
	}
	
	
	/**
	 *
	 * 
	 * @param request
	 */
	public ResolvedAuthorizationRequest resolve(final AuthorizationRequest request)
		throws ResolveException {
	
		JSONObject requestObject = null;
		
		if (request.hasRequestObject()) {
		
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
		
		
		// Resolve claims
		
		// IDTokenClaimsRequest idTokenClaimsRequest = new IDTokenClaimsRequest(rts);
		
		
		return null;
	}
}
