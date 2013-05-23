package com.nimbusds.openid.connect.sdk.op;


import java.io.IOException;
import java.net.URL;

import net.jcip.annotations.ThreadSafe;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseTypeSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.util.DefaultResourceRetriever;
import com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder;
import com.nimbusds.openid.connect.sdk.util.JWTDecoder;
import com.nimbusds.openid.connect.sdk.util.Resource;
import com.nimbusds.openid.connect.sdk.util.ResourceRetriever;



/**
 * OpenID Connect authorisation request resolver. Takes in a raw 
 * {@link com.nimbusds.openid.connect.sdk.OIDCAuthorizationRequest} and if a
 * request object is specified applies it to derive the final authorisation 
 * request parameters.
 *
 * <p>To process request objects the resolver must be supplied with a
 * {@link com.nimbusds.openid.connect.sdk.util.ResourceRetriever retriever} for
 * remote JWT objects and a 
 * {@link com.nimbusds.openid.connect.sdk.util.JWTDecoder decoder} to handle
 * their decoding and JWS validation and / or JWE decryption.
 *
 * <p>This class is thread-safe.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.9.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@ThreadSafe
public class OIDCAuthorizationRequestResolver {


	/**
	 * Retriever for JWTs passed by URL.
	 */
	private final ResourceRetriever jwtRetriever;
	
	
	/**
	 * Decoder for JWTs.
	 */
	private final JWTDecoder jwtDecoder;
	
	
	/**
	 * Creates a new OpenID Connect authorisation request resolver with a 
	 * {@link com.nimbusds.openid.connect.sdk.util.DefaultResourceRetriever
	 * default retriever} for JWTs passed by URL.
	 *
	 * @param jwtDecoder A configured JWT decoder and JWS validator / JWE 
	 *                   decryptor for the optional request objects. Must
	 *                   not be {@code null}.
	 */
	public OIDCAuthorizationRequestResolver(final JWTDecoder jwtDecoder) {
	
		this(new DefaultResourceRetriever(), jwtDecoder);
	}
	
	
	/**
	 * Creates a new OpenID Connect authorisation request resolver.
	 *
	 * @param jwtRetriever A configured retriever for optional request
	 *                     objects passed by URL. Must not be {@code null}.
	 * @param jwtDecoder   A configured JWT decoder and JWS validator / JWE 
	 *                     decryptor for the optional request objects. Must
	 *                     not be {@code null}.
	 */
	public OIDCAuthorizationRequestResolver(final ResourceRetriever jwtRetriever,
	                                        final JWTDecoder jwtDecoder) {
		
		this.jwtRetriever = jwtRetriever;
		this.jwtDecoder = jwtDecoder;
	}
	
	
	/**
	 * Gets the JWT retriever.
	 *
	 * @return The JWT retriever.
	 */
	public ResourceRetriever getJWTRetriever() {
	
		return jwtRetriever;
	}
	
	
	/**
	 * Gets the JWT decoder.
	 *
	 * @return The JWT decoder.
	 */
	public JWTDecoder getJWTDecoder() {
	
		return jwtDecoder;
	}
	
	
	/**
	 * Downloads an OpenID Connect request object from the specified URL.
	 * The content type of the URL resource is not checked.
	 *
	 * @param url The URL of the request object. Must not be {@code null}.
	 *
	 * @return The downloaded request object JWT.
	 *
	 * @throws ResolveException If the request object couldn't be 
	 *                          downloaded or parsed to a JWT.
	 */
	private JWT downloadRequestObject(final URL url)
		throws ResolveException {
	
		Resource resource = null;

		try {
			resource = jwtRetriever.retrieveResource(url);
			
		} catch (IOException e) {

			throw new ResolveException("Couldn't download OpenID Connect request object: " + 
				                   e.getMessage(), e);
		}

		try {
			return JWTParser.parse(resource.getContent());
		
		} catch (java.text.ParseException e) {

			throw new ResolveException("Couldn't parse OpenID Connect request object: " +
				                   e.getMessage(), e);
		}
	}
	
	
	/**
	 * Decodes the specified OpenID Connect request object, and if its
	 * secured performs additional JWS signature validation and / or JWE
	 * decryption.
	 *
	 * @param requestObject The request object to decode. Must not be 
	 *                      {@code null}.
	 *
	 * @return The JWT claims of the request object.
	 *
	 * @throws ResolveException If JWT decoding, JWS validation or JWE
	 *                          decryption failed.
	 */
	private ReadOnlyJWTClaimsSet decodeRequestObject(final JWT requestObject)
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

			if (! scope.contains(OIDCScopeToken.OPENID))
				throw new ResolveException("The scope must include an \"openid\" token");
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
		if (request.hasRequestJWT()) {
		
			JOSEObject encodedRequestObject = null;
		
			if (request.getRequestJWTURI() != null) {
			
				// The request object must be downloaded from URI
				try {
					encodedRequestObject = downloadRequestObject(request.getRequestJWTURI());

				} catch (ResolveException e) {

					throw new ResolveException(e.getMessage(), OIDCError.INVALID_REQUEST_URI, 
						                   redirectURI, state, e);
				}

			} else {
				// The request object is inlined
				encodedRequestObject = null; // TODO request.getRequestJWT();
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

			throw new ResolveException(e.getMessage(), 
				                   OAuth2Error.INVALID_REQUEST,
				                   redirectURI, state, e);
		}

		
		return new ResolvedOIDCAuthorizationRequest(rts, clientID, redirectURI,
		                                            nonce, state, display, prompt, idTokenHint, loginHint,
							    idTokenClaimsRequest, userInfoClaimsRequest);
	}
}
