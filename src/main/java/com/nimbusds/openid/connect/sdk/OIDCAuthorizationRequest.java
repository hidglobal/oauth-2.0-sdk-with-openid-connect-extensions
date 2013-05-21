package com.nimbusds.openid.connect.sdk;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseTypeSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;

import com.nimbusds.openid.connect.sdk.claims.ACR;


/**
 * OpenID Connect authorisation request. Used to authenticate (if required) an 
 * end-user and request the end-user's authorisation to release information to 
 * the client. This class is immutable.
 *
 * <p>Example HTTP request (code flow):
 *
 * <pre>
 * https://server.example.com/op/authorize?
 * response_type=code%20id_token
 * &amp;client_id=s6BhdRkqt3
 * &amp;redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * &amp;scope=openid
 * &amp;nonce=n-0S6_WzA2Mj
 * &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 *     <li>OpenID Connect Standard 1.0, section 2.3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class OIDCAuthorizationRequest extends AuthorizationRequest {
	
	
	/**
	 * The nonce (required for implicit flow, optional for code flow).
	 */
	private final Nonce nonce;
	
	
	/**
	 * The requested display type (optional).
	 */
	private final Display display;
	
	
	/**
	 * The requested prompt (optional).
	 */
	private final Prompt prompt;


	/**
	 * The required maximum authentication age, in seconds, 0 if not 
	 * specified (optional).
	 */
	private final int maxAge;


	/**
	 * The end-user's preferred languages and scripts for the user 
	 * interface (optional).
	 */
	private final List<LangTag> uiLocales;


	/**
	 * The end-user's preferred languages and scripts for claims being 
	 * returned (optional).
	 */
	private final List<LangTag> claimsLocales;


	/**
	 * Previously issued ID Token passed to the authorization server as a 
	 * hint about the end-user's current or past authenticated session with
	 * the client (optional). Should be present when {@code prompt=none} is 
	 * used.
	 */
	private final JWT idTokenHint;


	/**
	 * Hint to the authorization server about the login identifier the 
	 * end-user may use to log in (optional).
	 */
	private final String loginHint;


	/**
	 * Requested Authentication Context Class Reference values (optional).
	 */
	private final List<ACR> acrValues;


	/**
	 * Specific claims to be returned (optional).
	 */
	private final Object claims;
	
	
	/**
	 * Request JWT (optional).
	 */
	private final JWT requestJWT;
	
	
	/**
	 * Request object JWT URL (optional).
	 */
	private final URL requestURI;
	
	
	/**
	 * Creates a new minimal OpenID Connect authorisation request.
	 *
	 * @param rts         The response type set. Corresponds to the 
	 *                    {@code response_type} parameter. Must not be
	 *                    {@code null}.
	 * @param scope       The request scope. Corresponds to the
	 *                    {@code scope} parameter. Must not be 
	 *                    {@code null}.
	 * @param clientID    The client identifier. Corresponds to the
	 *                    {@code client_id} parameter. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The redirection URI. Corresponds to the
	 *                    {@code redirect_uri} parameter. Must not be 
	 *                    {@code null}.
	 * @param state       The state. Corresponds to the {@code state}
	 *                    parameter. May be {@code null}.
	 * @param nonce       The nonce. Corresponds to the {@code nonce} 
	 *                    parameter. May be {@code null} for code flow.
	 */
	public OIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                final Scope scope,
				        final ClientID clientID,
				        final URL redirectURI,
				        final State state,
				        final Nonce nonce) {

		// Not specified: display, prompt, maxAge, uiLocales, claimsLocales, 
		// idTokenHint, loginHint, acrValues, claims
		this(rts, scope, clientID, redirectURI, state, nonce, 
		     null, null, 0, null, null, 
		     null, null, null, null);
	}
	
	
	/**
	 * Creates a new OpenID Connect authorisation request without a request
	 * JWT.
	 *
	 * @param rts           The response type set. Corresponds to the 
	 *                      {@code response_type} parameter. Must not be
	 *                      {@code null}.
	 * @param scope         The request scope. Corresponds to the
	 *                      {@code scope} parameter. Must contain an
	 *                      {@link OIDCScopeToken#OPENID openid token}. 
	 *                      Must not be {@code null}.
	 * @param clientID      The client identifier. Corresponds to the
	 *                      {@code client_id} parameter. Must not be 
	 *                      {@code null}.
	 * @param redirectURI   The redirection URI. Corresponds to the
	 *                      {@code redirect_uri} parameter. Must not be 
	 *                      {@code null}.
	 * @param state         The state. Corresponds to the recommended 
	 *                      {@code state} parameter. {@code null} if not 
	 *                      specified.
	 * @param nonce         The nonce. Corresponds to the {@code nonce} 
	 *                      parameter. May be {@code null} for code flow.
	 * @param display       The requested display type. Corresponds to the 
	 *                      optional {@code display} parameter. 
	 *                      {@code null} if not specified.
	 * @param prompt        The requested prompt. Corresponds to the 
	 *                      optional {@code prompt} parameter. {@code null} 
	 *                      if not specified.
	 * @param maxAge        The required maximum authentication age, in
	 *                      seconds. Corresponds to the optional 
	 *                      {@code max_age} parameter. Zero if not 
	 *                      specified.
	 * @param uiLocales     The preferred languages and scripts for the 
	 *                      user interface. Corresponds to the optional 
	 *                      {@code ui_locales} parameter. {@code null} if 
	 *                      not specified.
	 * @param claimsLocales The preferred languages and scripts for claims
	 *                      being returned. Corresponds to the optional
	 *                      {@code claims_locales} parameter. {@code null}
	 *                      if not specified.
	 * @param idTokenHint   The ID Token hint. Corresponds to the optional 
	 *                      {@code id_token_hint} parameter. {@code null} 
	 *                      if not specified.
	 * @param loginHint     The login hint. Corresponds to the optional
	 *                      {@code login_hint} parameter. {@code null} if 
	 *                      not specified.
	 * @param acrValues     The requested Authentication Context Class
	 *                      Reference values. Corresponds to the optional
	 *                      {@code acr_values} parameter. {@code null} if
	 *                      not specified.
	 * @param claims        The specified claims to be returned. 
	 *                      Corresponds to the optional {@code claims}
	 *                      parameter. {@code null} if not specified.
	 */
	public OIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                final Scope scope,
				        final ClientID clientID,
				        final URL redirectURI,
				        final State state,
				        final Nonce nonce,
				        final Display display,
				        final Prompt prompt,
				        final int maxAge,
				        final List<LangTag> uiLocales,
				        final List<LangTag> claimsLocales,
				        final JWT idTokenHint,
				        final String loginHint,
				        final List<ACR> acrValues,
				        final Object claims) {
				    
				    
		this(rts, scope, clientID, redirectURI, state, nonce, display, prompt,
		     maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues,
		     claims, (JWT)null);
	}
	
	
	/**
	 * Creates a new OpenID Connect authorisation request with a request 
	 * JWT specified by value.
	 *
	 * @param rts           The response type set. Corresponds to the 
	 *                      {@code response_type} parameter. Must not be
	 *                      {@code null}.
	 * @param scope         The request scope. Corresponds to the
	 *                      {@code scope} parameter. Must contain an
	 *                      {@link OIDCScopeToken#OPENID openid token}. 
	 *                      Must not be {@code null}.
	 * @param clientID      The client identifier. Corresponds to the
	 *                      {@code client_id} parameter. Must not be 
	 *                      {@code null}.
	 * @param redirectURI   The redirection URI. Corresponds to the
	 *                      {@code redirect_uri} parameter. Must not be 
	 *                      {@code null}.
	 * @param state         The state. Corresponds to the recommended 
	 *                      {@code state} parameter. {@code null} if not 
	 *                      specified.
	 * @param nonce         The nonce. Corresponds to the {@code nonce} 
	 *                      parameter. May be {@code null} for code flow.
	 * @param display       The requested display type. Corresponds to the 
	 *                      optional {@code display} parameter. 
	 *                      {@code null} if not specified.
	 * @param prompt        The requested prompt. Corresponds to the 
	 *                      optional {@code prompt} parameter. {@code null} 
	 *                      if not specified.
	 * @param maxAge        The required maximum authentication age, in
	 *                      seconds. Corresponds to the optional 
	 *                      {@code max_age} parameter. Zero if not 
	 *                      specified.
	 * @param uiLocales     The preferred languages and scripts for the 
	 *                      user interface. Corresponds to the optional 
	 *                      {@code ui_locales} parameter. {@code null} if 
	 *                      not specified.
	 * @param claimsLocales The preferred languages and scripts for claims
	 *                      being returned. Corresponds to the optional
	 *                      {@code claims_locales} parameter. {@code null}
	 *                      if not specified.
	 * @param idTokenHint   The ID Token hint. Corresponds to the optional 
	 *                      {@code id_token_hint} parameter. {@code null} 
	 *                      if not specified.
	 * @param loginHint     The login hint. Corresponds to the optional
	 *                      {@code login_hint} parameter. {@code null} if 
	 *                      not specified.
	 * @param acrValues     The requested Authentication Context Class
	 *                      Reference values. Corresponds to the optional
	 *                      {@code acr_values} parameter. {@code null} if
	 *                      not specified.
	 * @param claims        The specified claims to be returned. 
	 *                      Corresponds to the optional {@code claims}
	 *                      parameter. {@code null} if not specified.
	 * @param requestJWT    The request JWT. Corresponds to the optional
	 *                      {@code request} parameter. {@code null} if not
	 *                      specified.
	 */
	public OIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                final Scope scope,
				        final ClientID clientID,
				        final URL redirectURI,
				        final State state,
				        final Nonce nonce,
				        final Display display,
				        final Prompt prompt,
				        final int maxAge,
				        final List<LangTag> uiLocales,
				        final List<LangTag> claimsLocales,
				        final JWT idTokenHint,
				        final String loginHint,
				        final List<ACR> acrValues,
				        final Object claims,
				        final JWT requestJWT) {
				    
		super(rts, clientID, redirectURI, scope, state);

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");

		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");

		if (! scope.contains(OIDCScopeToken.OPENID))
			throw new IllegalArgumentException("The scope must include an \"openid\" token");
		
		
		// Nonce required for implicit protocol flow
		if (rts.impliesImplicitFlow() && nonce == null)
			throw new IllegalArgumentException("Nonce is required in implicit protocol flow");
		
		this.nonce = nonce;
		
		// Optional parameters
		this.display = display;
		this.prompt = prompt;
		this.maxAge = maxAge;

		if (uiLocales != null)
			this.uiLocales = Collections.unmodifiableList(uiLocales);
		else
			this.uiLocales = null;

		if (claimsLocales != null)
			this.claimsLocales = Collections.unmodifiableList(claimsLocales);
		else
			this.claimsLocales = null;

		this.idTokenHint = idTokenHint;
		this.loginHint = loginHint;

		if (acrValues != null)
			this.acrValues = Collections.unmodifiableList(acrValues);
		else
			this.acrValues = null;

		this.claims = claims;
		this.requestJWT = requestJWT;
		this.requestURI = null;
	}
	
	
	/**
	 * Creates a new OpenID Connect authorisation request with a request 
	 * JWT specified by URI reference.
	 *
	 * @param rts           The response type set. Corresponds to the 
	 *                      {@code response_type} parameter. Must not be
	 *                      {@code null}.
	 * @param scope         The request scope. Corresponds to the
	 *                      {@code scope} parameter. Must contain an
	 *                      {@link OIDCScopeToken#OPENID openid token}. 
	 *                      Must not be {@code null}.
	 * @param clientID      The client identifier. Corresponds to the
	 *                      {@code client_id} parameter. Must not be 
	 *                      {@code null}.
	 * @param redirectURI   The redirection URI. Corresponds to the
	 *                      {@code redirect_uri} parameter. Must not be 
	 *                      {@code null}.
	 * @param state         The state. Corresponds to the recommended 
	 *                      {@code state} parameter. {@code null} if not 
	 *                      specified.
	 * @param nonce         The nonce. Corresponds to the {@code nonce} 
	 *                      parameter. May be {@code null} for code flow.
	 * @param display       The requested display type. Corresponds to the 
	 *                      optional {@code display} parameter. 
	 *                      {@code null} if not specified.
	 * @param prompt        The requested prompt. Corresponds to the 
	 *                      optional {@code prompt} parameter. {@code null} 
	 *                      if not specified.
	 * @param maxAge        The required maximum authentication age, in
	 *                      seconds. Corresponds to the optional 
	 *                      {@code max_age} parameter. Zero if not 
	 *                      specified.
	 * @param uiLocales     The preferred languages and scripts for the 
	 *                      user interface. Corresponds to the optional 
	 *                      {@code ui_locales} parameter. {@code null} if 
	 *                      not specified.
	 * @param claimsLocales The preferred languages and scripts for claims
	 *                      being returned. Corresponds to the optional
	 *                      {@code claims_locales} parameter. {@code null}
	 *                      if not specified.
	 * @param idTokenHint   The ID Token hint. Corresponds to the optional 
	 *                      {@code id_token_hint} parameter. {@code null} 
	 *                      if not specified.
	 * @param loginHint     The login hint. Corresponds to the optional
	 *                      {@code login_hint} parameter. {@code null} if 
	 *                      not specified.
	 * @param acrValues     The requested Authentication Context Class
	 *                      Reference values. Corresponds to the optional
	 *                      {@code acr_values} parameter. {@code null} if
	 *                      not specified.
	 * @param claims        The specified claims to be returned. 
	 *                      Corresponds to the optional {@code claims}
	 *                      parameter. {@code null} if not specified.
	 * @param requestURI    The request JWT URI. Corresponds to the 
	 *                      optional {@code request_uri} parameter. 
	 *                      {@code null} if not specified.
	 */
	public OIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                final Scope scope,
				        final ClientID clientID,
				        final URL redirectURI,
				        final State state,
				        final Nonce nonce,
				        final Display display,
				        final Prompt prompt,
				        final int maxAge,
				        final List<LangTag> uiLocales,
				        final List<LangTag> claimsLocales,
				        final JWT idTokenHint,
				        final String loginHint,
				        final List<ACR> acrValues,
				        final Object claims,
				        final URL requestURI) {
				    
		super(rts, clientID, redirectURI, scope, state);

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");

		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");

		if (! scope.contains(OIDCScopeToken.OPENID))
			throw new IllegalArgumentException("The scope must include an \"openid\" token");
		
		
		// Nonce required for implicit protocol flow
		if (rts.impliesImplicitFlow() && nonce == null)
			throw new IllegalArgumentException("Nonce is required in implicit protocol flow");
		
		this.nonce = nonce;
		
		// Optional parameters
		// Optional parameters
		this.display = display;
		this.prompt = prompt;
		this.maxAge = maxAge;

		if (uiLocales != null)
			this.uiLocales = Collections.unmodifiableList(uiLocales);
		else
			this.uiLocales = null;

		if (claimsLocales != null)
			this.claimsLocales = Collections.unmodifiableList(claimsLocales);
		else
			this.claimsLocales = null;

		this.idTokenHint = idTokenHint;
		this.loginHint = loginHint;

		if (acrValues != null)
			this.acrValues = Collections.unmodifiableList(acrValues);
		else
			this.acrValues = null;

		this.claims = claims;
		this.requestJWT = null;
		this.requestURI = requestURI;
	}
	
	
	/**
	 * Gets the nonce. Corresponds to the conditionally optional 
	 * {@code nonce} parameter.
	 *
	 * @return The nonce, {@code null} if not specified.
	 */
	public Nonce getNonce() {
	
		return nonce;
	}
	
	
	/**
	 * Gets the requested display type. Corresponds to the optional
	 * {@code display} parameter.
	 *
	 * @return The requested display type, {@code null} if not specified.
	 */
	public Display getDisplay() {
	
		return display;
	}
	
	
	/**
	 * Gets the requested prompt. Corresponds to the optional 
	 * {@code prompt} parameter.
	 *
	 * @return The requested prompt, {@code null} if not specified.
	 */
	public Prompt getPrompt() {
	
		return prompt;
	}


	/**
	 * Gets the required maximum authentication age. Corresponds to the
	 * optional {@code max_age} parameter.
	 *
	 * @return The maximum authentication age, in seconds; 0 if not 
	 *         specified.
	 */
	public int getMaxAge() {
	
		return maxAge;
	}


	/**
	 * Gets the end-user's preferred languages and scripts for the user
	 * interface, ordered by preference. Corresponds to the optional
	 * {@code ui_locales} parameter.
	 *
	 * @return The preferred UI locales, {@code null} if not specified.
	 */
	public List<LangTag> getUILocales() {

		return uiLocales;
	}


	/**
	 * Gets the end-user's preferred languages and scripts for the claims
	 * being returned, ordered by preference. Corresponds to the optional
	 * {@code claims_locales} parameter.
	 *
	 * @return The preferred claims locales, {@code null} if not specified.
	 */
	public List<LangTag> getClaimsLocales() {

		return claimsLocales;
	}


	/**
	 * Gets the ID Token hint. Corresponds to the conditionally optional 
	 * {@code id_token_hint} parameter.
	 *
	 * @return The ID Token hint, {@code null} if not specified.
	 */
	public JWT getIDTokenHint() {
	
		return idTokenHint;
	}


	/**
	 * Gets the login hint. Corresponds to the optional {@code login_hint} 
	 * parameter.
	 *
	 * @return The login hint, {@code null} if not specified.
	 */
	public String getLoginHint() {

		return loginHint;
	}


	/**
	 * Gets the requested Authentication Context Class Reference values.
	 * Corresponds to the optional {@code acr_values} parameter.
	 *
	 * @return The requested ACR values, {@code null} if not specified.
	 */
	public List<ACR> getACRValues() {

		return acrValues;
	}


	/**
	 * Gets the specific claims to return. Corresponds to the optional
	 * {@code claims} parameter.
	 *
	 * @return The specific claims to return, {@code null} if not
	 *         specified.
	 */
	public Object getClaims() {

		return claims;
	}
	
	
	/**
	 * Gets the request JWT. Corresponds to the optional {@code request} 
	 * parameter.
	 *
	 * @return The request JWT, {@code null} if not specified.
	 */
	public JWT getRequestJWT() {
	
		return requestJWT;
	}
	
	
	/**
	 * Gets the request JWT URI. Corresponds to the optional 
	 * {@code request_uri} parameter.
	 *
	 * @return The request JWT URI, {@code null} if not specified.
	 */
	public URL getRequestJWTURI() {
	
		return requestURI;
	}
	
	
	/**
	 * Returns {@code true} if this authorisation request has a request JWT
	 * included in the {@code request} parameter or referenced through the 
	 * {@code request_uri} parameter).
	 *
	 * @return {@code true} if a request JWT is specified, else 
	 *         {@code false}.
	 */
	public boolean hasRequestJWT() {
	
		if (requestJWT != null || requestURI != null) {
			return true;
		} else {
			return false;
		}
	}


	@Override
	public Map<String,String> toParameters()
		throws SerializeException {

		Map <String,String> params = super.toParameters();
		
		if (nonce != null)
			params.put("nonce", nonce.toString());
		
		if (display != null)
			params.put("display", display.toString());
		
		if (prompt != null)
			params.put("prompt", prompt.toString());

		if (maxAge > 0)
			params.put("max_age", "" + maxAge);

		if (uiLocales != null)
			params.put("ui_locales", null);

		if (claimsLocales != null)
			params.put("claims_locales", null);

		if (idTokenHint != null) {
		
			try {
				params.put("id_token_hint", idTokenHint.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize ID token hint: " + e.getMessage(), e);
			}
		}

		if (loginHint != null)
			params.put("login_hint", loginHint);

		if (acrValues != null)
			params.put("acr_values", null);

		if (claims != null)
			params.put("claims", null);
		
		
		// Request EXOR request_uri check done by setter methods
		
		if (requestJWT != null) {
		
			try {
				params.put("request", requestJWT.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize request JWT: " + e.getMessage(), e);
			}
		}
		
		if (requestURI != null)
			params.put("request_uri", requestURI.toString());

		return params;
	}


	/**
	 * Parses an OpenID Connect authorisation request from the specified 
	 * parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = token id_token
	 * client_id     = s6BhdRkqt3
	 * redirect_uri  = https://client.example.com/cb
	 * scope         =  openid profile
	 * state         =  af0ifjsldkj
	 * nonce         =  -0S6_WzA2Mj
	 * </pre>
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authorisation request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authorisation request.
	 */
	public static OIDCAuthorizationRequest parse(final Map<String,String> params)
		throws ParseException {

		AuthorizationRequest ar = AuthorizationRequest.parse(params);

		URL redirectURI = ar.getRedirectURI();

		if (redirectURI == null)
			throw new ParseException("Missing \"redirect_uri\" parameter", 
				                 OAuth2Error.INVALID_REQUEST);

		State state = ar.getState();

		ResponseTypeSet rts = ar.getResponseTypeSet();

		for (ResponseType rt: rts) {

			if (! rt.equals(ResponseType.CODE) &&
			    ! rt.equals(ResponseType.TOKEN) &&
			    ! rt.equals(OIDCResponseType.ID_TOKEN) )
				throw new ParseException("Unsupported \"response_type\" parameter: " + rt, 
					                 OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, 
					                 redirectURI, state, null);
		}
		
		Scope scope = ar.getScope();

		if (scope == null)
			throw new ParseException("Missing \"scope\" parameter", 
				                 OAuth2Error.INVALID_REQUEST, 
					         redirectURI, state, null);

		if (! scope.contains(OIDCScopeToken.OPENID))
			throw new ParseException("The scope must include an \"openid\" token",
				                 OAuth2Error.INVALID_REQUEST, 
					         redirectURI, state, null);

		ClientID clientID = ar.getClientID();


		// Parse OIDC parameters

		Nonce nonce = Nonce.parse(params.get("nonce"));
		
		// Nonce required in implicit flow
		if (rts.impliesImplicitFlow() && nonce == null)
			throw new ParseException("Missing \"nonce\" parameter",
				                 OAuth2Error.INVALID_REQUEST,
				                 redirectURI, state, null);
		

		Display display = null;
		
		try {
			display = Display.parse(params.get("display"));

		} catch (ParseException e) {

			throw new ParseException("Invalid \"display\" parameter: " + e.getMessage(), 
				                 OAuth2Error.INVALID_REQUEST,
				                 redirectURI, state, e);
		}
		
		
		Prompt prompt = null;
		
		try {
			prompt = Prompt.parse(params.get("prompt"));
				
		} catch (ParseException e) {
			
			throw new ParseException("Invalid \"prompt\" parameter: " + e.getMessage(), 
				                 OAuth2Error.INVALID_REQUEST,
				                 redirectURI, state, e);
		}


		String v = params.get("max_age");

		int maxAge = 0;

		if (StringUtils.isNotBlank(v)) {

			try {
				maxAge = Integer.parseInt(v);

			} catch (NumberFormatException e) {

				throw new ParseException("Invalid \"max_age\" parameter: " + e.getMessage(),
					                 OAuth2Error.INVALID_REQUEST,
					                 redirectURI, state, e);
			}
		}


		v = params.get("ui_locales");

		List<LangTag> uiLocales = null;

		if (StringUtils.isNotBlank(v)) {

			uiLocales = new LinkedList<LangTag>();

			for (String s: v.split("\\s+")) {

				try {
					uiLocales.add(LangTag.parse(s));

				} catch (LangTagException e) {

					throw new ParseException("Invalid \"ui_locales\" parameter: " + e.getMessage(),
						                 OAuth2Error.INVALID_REQUEST,
						                 redirectURI, state, e);
				}
			}
		}


		v = params.get("claims_locales");

		List<LangTag> claimsLocales = null;

		if (StringUtils.isNotBlank(v)) {

			claimsLocales = new LinkedList<LangTag>();

			for (String s: v.split("\\s+")) {

				try {
					claimsLocales.add(LangTag.parse(s));

				} catch (LangTagException e) {

					throw new ParseException("Invalid \"claims_locales\" parameter: " + e.getMessage(),
						                 OAuth2Error.INVALID_REQUEST,
						                 redirectURI, state, e);
				}
			}
		}


		v = params.get("id_token_hint");
		
		JWT idTokenHint = null;
		
		if (StringUtils.isNotBlank(v)) {
		
			try {
				idTokenHint = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
		
				throw new ParseException("Invalid \"id_token_hint\" parameter: " + e.getMessage(), 
					                 OAuth2Error.INVALID_REQUEST,
					                 redirectURI, state, e);
			}
		}

		String loginHint = params.get("login_hint");


		v = params.get("acr_values");

		List<ACR> acrValues = null;

		if (StringUtils.isNotBlank(v)) {

			acrValues = new LinkedList<ACR>();

			for (String s: v.split("\\s+")) {

				acrValues.add(new ACR(s));
			}
		}


		v = params.get("claims");

		Object claims = null;
		
		
		v = params.get("request");
		
		JWT requestJWT = null;
		
		if (StringUtils.isNotBlank(v)) {
		
			try {
				requestJWT = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
			
				throw new ParseException("Invalid \"request\" parameter: " + e.getMessage(), 
					                 OIDCError.INVALID_OPENID_REQUEST_OBJECT,
					                 redirectURI, state, e);
			}
		}
		
		
		v = params.get("request_uri");
		
		URL requestURI = null;
		
		if (StringUtils.isNotBlank(v)) {
	
			// request_object and request_uri must not be defined at the same time
			if (requestJWT != null)
				throw new ParseException("Invalid request: Found mutually exclusive \"request_object\" and \"request_uri\" parameters",
					                 OAuth2Error.INVALID_REQUEST,
					                 redirectURI, state, null);
	
			try {
				requestURI = new URL(v);
		
			} catch (MalformedURLException e) {
			
				throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), 
					                 OAuth2Error.INVALID_REQUEST,
					                 redirectURI, state, e);
			}
		}
	
		// Select appropriate constructor
		
		// Inline request object
		if (requestJWT != null)
			return new OIDCAuthorizationRequest(rts, scope, clientID, redirectURI, state, nonce,
			                                    display, prompt, maxAge, uiLocales, claimsLocales, 
			                                    idTokenHint, loginHint, acrValues, claims, requestJWT);
	
		// Request object by URL reference
		if (requestURI != null)
			return new OIDCAuthorizationRequest(rts, scope, clientID, redirectURI, state, nonce,
			                                    display, prompt, maxAge, uiLocales, claimsLocales, 
			                                    idTokenHint, loginHint, acrValues, claims, requestURI);
		
		// No request object or URI
		return new OIDCAuthorizationRequest(rts, scope, clientID, redirectURI, state, nonce,
			                            display, prompt, maxAge, uiLocales, claimsLocales, 
			                            idTokenHint, loginHint, acrValues, claims);
	}
	
	
	/**
	 * Parses an OpenID Connect authorisation request from the specified 
	 * URL query string.
	 *
	 * <p>Example URL query string:
	 *
	 * <pre>
	 * response_type=token%20id_token
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &amp;scope=openid%20profile
	 * &amp;state=af0ifjsldkj
	 * &amp;nonce=n-0S6_WzA2Mj
	 * </pre>
	 *
	 * @param query The URL query string. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authorisation request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an 
	 *                        OpenID Connect authorisation request.
	 */
	public static OIDCAuthorizationRequest parse(final String query)
		throws ParseException {
	
		return parse(URLUtils.parseParameters(query));
	}
	
	
	/**
	 * Parses an authorisation request from the specified HTTP GET or HTTP
	 * POST request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * https://server.example.com/op/authorize?
	 * response_type=code%20id_token
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &amp;scope=openid
	 * &amp;nonce=n-0S6_WzA2Mj
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authorisation request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an 
	 *                        OpenID Connect authorisation request.
	 */
	public static AuthorizationRequest parse(final HTTPRequest httpRequest) 
		throws ParseException {
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing URL query string");
		
		return parse(query);
	}
}
