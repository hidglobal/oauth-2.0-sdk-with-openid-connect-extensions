package com.nimbusds.openid.connect.sdk;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;

import com.nimbusds.openid.connect.sdk.claims.ACR;


/**
 * OpenID Connect authentication request. Intended to authenticate an end-user
 * and request the end-user's authorisation to release information to the
 * client.
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
 *     <li>OpenID Connect Core 1.0, section 3.1.2.1.
 * </ul>
 */
@Immutable
public final class AuthenticationRequest extends AuthorizationRequest {
	
	
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
	 * Previously issued ID Token passed to the authorisation server as a 
	 * hint about the end-user's current or past authenticated session with
	 * the client (optional). Should be present when {@code prompt=none} is 
	 * used.
	 */
	private final JWT idTokenHint;


	/**
	 * Hint to the authorisation server about the login identifier the 
	 * end-user may use to log in (optional).
	 */
	private final String loginHint;


	/**
	 * Requested Authentication Context Class Reference values (optional).
	 */
	private final List<ACR> acrValues;


	/**
	 * Individual claims to be returned (optional).
	 */
	private final ClaimsRequest claims;
	
	
	/**
	 * Request object (optional).
	 */
	private final JWT requestObject;
	
	
	/**
	 * Request object URL (optional).
	 */
	private final URL requestURI;
	
	
	/**
	 * Creates a new minimal OpenID Connect authentication request.
	 *
	 * @param uri         The URI of the OAuth 2.0 authorisation endpoint.
	 *                    May be {@code null} if the {@link #toHTTPRequest}
	 *                    method will not be used.
	 * @param rt          The response type. Corresponds to the 
	 *                    {@code response_type} parameter. Must specify a
	 *                    valid OpenID Connect response type. Must not be
	 *                    {@code null}.
	 * @param scope       The request scope. Corresponds to the
	 *                    {@code scope} parameter. Must contain an
	 *                    {@link OIDCScopeValue#OPENID openid value}. Must
	 *                    not be {@code null}.
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
	public AuthenticationRequest(final URL uri,
				     final ResponseType rt,
				     final Scope scope,
				     final ClientID clientID,
				     final URL redirectURI,
				     final State state,
				     final Nonce nonce) {

		// Not specified: display, prompt, maxAge, uiLocales, claimsLocales, 
		// idTokenHint, loginHint, acrValues, claims
		this(uri, rt, scope, clientID, redirectURI, state, nonce, 
		     null, null, 0, null, null, 
		     null, null, null, null);
	}
	
	
	/**
	 * Creates a new OpenID Connect authentication request without a request
	 * object.
	 *
	 * @param uri           The URI of the OAuth 2.0 authorisation
	 *                      endpoint. May be {@code null} if the
	 *                      {@link #toHTTPRequest} method will not be used.
	 * @param rt            The response type. Corresponds to the 
	 *                      {@code response_type} parameter. Must specify a
	 *                      valid OpenID Connect response type. Must not be
	 *                      {@code null}.
	 * @param scope         The request scope. Corresponds to the
	 *                      {@code scope} parameter. Must contain an
	 *                      {@link OIDCScopeValue#OPENID openid value}. 
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
	 * @param claims        The individual claims to be returned. 
	 *                      Corresponds to the optional {@code claims} 
	 *                      parameter. {@code null} if not specified.
	 */
	public AuthenticationRequest(final URL uri,
				     final ResponseType rt,
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
				     final ClaimsRequest claims) {
				    
				    
		this(uri, rt, scope, clientID, redirectURI, state, nonce, display, prompt,
		     maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues,
		     claims, (JWT)null);
	}
	
	
	/**
	 * Creates a new OpenID Connect authentication request with a request
	 * object specified by value.
	 *
	 * @param uri           The URI of the OAuth 2.0 authorisation
	 *                      endpoint. May be {@code null} if the
	 *                      {@link #toHTTPRequest} method will not be used.
	 * @param rt            The response type set. Corresponds to the 
	 *                      {@code response_type} parameter. Must specify a
	 *                      valid OpenID Connect response type. Must not be
	 *                      {@code null}.
	 * @param scope         The request scope. Corresponds to the
	 *                      {@code scope} parameter. Must contain an
	 *                      {@link OIDCScopeValue#OPENID openid value}. 
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
	 * @param claims        The individual claims to be returned. 
	 *                      Corresponds to the optional {@code claims} 
	 *                      parameter. {@code null} if not specified.
	 * @param requestObject The request object. Corresponds to the optional
	 *                      {@code request} parameter. {@code null} if not
	 *                      specified.
	 */
	public AuthenticationRequest(final URL uri,
				     final ResponseType rt,
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
				     final ClaimsRequest claims,
				     final JWT requestObject) {
				    
		super(uri, rt, clientID, redirectURI, scope, state);

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
		
		OIDCResponseTypeValidator.validate(rt);

		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");

		if (! scope.contains(OIDCScopeValue.OPENID))
			throw new IllegalArgumentException("The scope must include an \"openid\" token");
		
		
		// Nonce required for implicit protocol flow
		if (rt.impliesImplicitFlow() && nonce == null)
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
		this.requestObject = requestObject;
		this.requestURI = null;
	}
	
	
	/**
	 * Creates a new OpenID Connect authentication request with a request
	 * object specified by URL.
	 *
	 * @param uri           The URI of the OAuth 2.00 authorisation
	 *                      endpoint. May be {@code null} if the
	 *                      {@link #toHTTPRequest} method will not be used.
	 * @param rt            The response type. Corresponds to the 
	 *                      {@code response_type} parameter. Must specify a
	 *                      a valid OpenID Connect response type. Must not 
	 *                      be {@code null}.
	 * @param scope         The request scope. Corresponds to the
	 *                      {@code scope} parameter. Must contain an
	 *                      {@link OIDCScopeValue#OPENID openid value}. 
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
	 * @param claims        The individual claims to be returned. 
	 *                      Corresponds to the optional {@code claims} 
	 *                      parameter. {@code null} if not specified.
	 * @param requestURI    The request object URL. Corresponds to the 
	 *                      optional {@code request_uri} parameter. 
	 *                      {@code null} if not specified.
	 */
	public AuthenticationRequest(final URL uri,
				     final ResponseType rt,
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
				     final ClaimsRequest claims,
				     final URL requestURI) {
				    
		super(uri, rt, clientID, redirectURI, scope, state);

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");

		OIDCResponseTypeValidator.validate(rt);
		
		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");

		if (! scope.contains(OIDCScopeValue.OPENID))
			throw new IllegalArgumentException("The scope must include an \"openid\" token");
		
		
		// Nonce required for implicit protocol flow
		if (rt.impliesImplicitFlow() && nonce == null)
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
		this.requestObject = null;
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
	 * Gets the individual claims to be returned. Corresponds to the 
	 * optional {@code claims} parameter.
	 *
	 * @return The individual claims to be returned, {@code null} if not
	 *         specified.
	 */
	public ClaimsRequest getClaims() {

		return claims;
	}
	
	
	/**
	 * Gets the request object. Corresponds to the optional {@code request} 
	 * parameter.
	 *
	 * @return The request object, {@code null} if not specified.
	 */
	public JWT getRequestObject() {
	
		return requestObject;
	}
	
	
	/**
	 * Gets the request object URL. Corresponds to the optional 
	 * {@code request_uri} parameter.
	 *
	 * @return The request object URL, {@code null} if not specified.
	 */
	public URL getRequestURI() {
	
		return requestURI;
	}
	
	
	/**
	 * Returns {@code true} if this authentication request specifies an
	 * OpenID Connect request object (directly through the {@code request} 
	 * parameter or by reference through the {@code request_uri} parameter).
	 *
	 * @return {@code true} if a request object is specified, else 
	 *         {@code false}.
	 */
	public boolean specifiesRequestObject() {
	
		if (requestObject != null || requestURI != null) {

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

		if (uiLocales != null) {

			StringBuilder sb = new StringBuilder();

			for (LangTag locale: uiLocales) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(locale.toString());
			}

			params.put("ui_locales", sb.toString());
		}

		if (claimsLocales != null) {

			StringBuilder sb = new StringBuilder();

			for (LangTag locale: claimsLocales) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(locale.toString());
			}

			params.put("claims_locales", sb.toString());
		}

		if (idTokenHint != null) {
		
			try {
				params.put("id_token_hint", idTokenHint.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize ID token hint: " + e.getMessage(), e);
			}
		}

		if (loginHint != null)
			params.put("login_hint", loginHint);

		if (acrValues != null) {

			StringBuilder sb = new StringBuilder();

			for (ACR acr: acrValues) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(acr.toString());
			}

			params.put("acr_values", sb.toString());
		}
			

		if (claims != null)
			params.put("claims", claims.toJSONObject().toString());
		
		if (requestObject != null) {
		
			try {
				params.put("request", requestObject.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize request object to JWT: " + e.getMessage(), e);
			}
		}
		
		if (requestURI != null)
			params.put("request_uri", requestURI.toString());

		return params;
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = token id_token
	 * client_id     = s6BhdRkqt3
	 * redirect_uri  = https://client.example.com/cb
	 * scope         = openid profile
	 * state         = af0ifjsldkj
	 * nonce         = -0S6_WzA2Mj
	 * </pre>
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final Map<String,String> params)
		throws ParseException {

		return parse(null, params);
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = token id_token
	 * client_id     = s6BhdRkqt3
	 * redirect_uri  = https://client.example.com/cb
	 * scope         = openid profile
	 * state         = af0ifjsldkj
	 * nonce         = -0S6_WzA2Mj
	 * </pre>
	 *
	 * @param uri    The URI of the OAuth 2.0 authorisation endpoint. May
	 *               be {@code null} if the {@link #toHTTPRequest} method
	 *               will not be used.
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final URL uri, final Map<String,String> params)
		throws ParseException {

		// Parse and validate the core OAuth 2.0 autz request params in 
		// the context of OIDC
		AuthorizationRequest ar = AuthorizationRequest.parse(uri, params);

		ClientID clientID = ar.getClientID();
		State state = ar.getState();

		// Required in OIDC
		URL redirectURI = ar.getRedirectionURI();

		if (redirectURI == null)
			throw new ParseException("Missing \"redirect_uri\" parameter", 
				                 OAuth2Error.INVALID_REQUEST, clientID, null, state);


		ResponseType rt = ar.getResponseType();
		
		try {
			OIDCResponseTypeValidator.validate(rt);
			
		} catch (IllegalArgumentException e) {
			
			throw new ParseException("Unsupported \"response_type\" parameter: " + e.getMessage(), 
					         OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, 
					         clientID, redirectURI, state);
		}
		
		// Required in OIDC, must include "openid" parameter
		Scope scope = ar.getScope();

		if (scope == null)
			throw new ParseException("Missing \"scope\" parameter", 
				                 OAuth2Error.INVALID_REQUEST, 
					         clientID, redirectURI, state);

		if (! scope.contains(OIDCScopeValue.OPENID))
			throw new ParseException("The scope must include an \"openid\" token",
				                 OAuth2Error.INVALID_REQUEST, 
					         clientID, redirectURI, state);




		// Parse the remaining OIDC parameters
		Nonce nonce = Nonce.parse(params.get("nonce"));
		
		// Nonce required in implicit flow
		if (rt.impliesImplicitFlow() && nonce == null)
			throw new ParseException("Missing \"nonce\" parameter: Required in implicit flow",
				                 OAuth2Error.INVALID_REQUEST,
				                 clientID, redirectURI, state);
		
		Display display;
		
		try {
			display = Display.parse(params.get("display"));

		} catch (ParseException e) {

			throw new ParseException("Invalid \"display\" parameter: " + e.getMessage(), 
				                 OAuth2Error.INVALID_REQUEST,
				                 clientID, redirectURI, state, e);
		}
		
		
		Prompt prompt;
		
		try {
			prompt = Prompt.parse(params.get("prompt"));
				
		} catch (ParseException e) {
			
			throw new ParseException("Invalid \"prompt\" parameter: " + e.getMessage(), 
				                 OAuth2Error.INVALID_REQUEST,
				                 clientID, redirectURI, state, e);
		}


		String v = params.get("max_age");

		int maxAge = 0;

		if (StringUtils.isNotBlank(v)) {

			try {
				maxAge = Integer.parseInt(v);

			} catch (NumberFormatException e) {

				throw new ParseException("Invalid \"max_age\" parameter: " + e.getMessage(),
					                 OAuth2Error.INVALID_REQUEST,
					                 clientID, redirectURI, state, e);
			}
		}


		v = params.get("ui_locales");

		List<LangTag> uiLocales = null;

		if (StringUtils.isNotBlank(v)) {

			uiLocales = new LinkedList<LangTag>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				try {
					uiLocales.add(LangTag.parse(st.nextToken()));

				} catch (LangTagException e) {

					throw new ParseException("Invalid \"ui_locales\" parameter: " + e.getMessage(),
						                 OAuth2Error.INVALID_REQUEST,
						                 clientID, redirectURI, state, e);
				}
			}
		}


		v = params.get("claims_locales");

		List<LangTag> claimsLocales = null;

		if (StringUtils.isNotBlank(v)) {

			claimsLocales = new LinkedList<LangTag>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				try {
					claimsLocales.add(LangTag.parse(st.nextToken()));

				} catch (LangTagException e) {

					throw new ParseException("Invalid \"claims_locales\" parameter: " + e.getMessage(),
						                 OAuth2Error.INVALID_REQUEST,
						                 clientID, redirectURI, state, e);
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
					                 clientID, redirectURI, state, e);
			}
		}

		String loginHint = params.get("login_hint");


		v = params.get("acr_values");

		List<ACR> acrValues = null;

		if (StringUtils.isNotBlank(v)) {

			acrValues = new LinkedList<ACR>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				acrValues.add(new ACR(st.nextToken()));
			}
		}


		v = params.get("claims");

		ClaimsRequest claims = null;

		if (StringUtils.isNotBlank(v)) {

			JSONObject jsonObject;

			try {
				jsonObject = JSONObjectUtils.parseJSONObject(v);

			} catch (ParseException e) {

				throw new ParseException("Invalid \"claims\" parameter: " + e.getMessage(),
					                 OAuth2Error.INVALID_REQUEST,
					                 clientID, redirectURI, state, e);
			}

			// Parse exceptions silently ignored
			claims = ClaimsRequest.parse(jsonObject);
		}
		
		
		v = params.get("request_uri");
		
		URL requestURI = null;
		
		if (StringUtils.isNotBlank(v)) {

			try {
				requestURI = new URL(v);
		
			} catch (MalformedURLException e) {
			
				throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), 
					                 OAuth2Error.INVALID_REQUEST,
					                 clientID, redirectURI, state, e);
			}
		}

		v = params.get("request");

		JWT requestObject = null;

		if (StringUtils.isNotBlank(v)) {

			// request_object and request_uri must not be defined at the same time
			if (requestURI != null) {

				throw new ParseException("Invalid request: Found mutually exclusive \"request\" and \"request_uri\" parameters",
					                 OAuth2Error.INVALID_REQUEST,
					                 clientID, redirectURI, state, null);
			}

			try {
				requestObject = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
		
				throw new ParseException("Invalid \"request_object\" parameter: " + e.getMessage(), 
					                 OAuth2Error.INVALID_REQUEST,
					                 clientID, redirectURI, state, e);
			}
		}
		
		
		// Select the appropriate constructor
		
		// Inline request object
		if (requestObject != null)
			return new AuthenticationRequest(uri, rt, scope, clientID, redirectURI, state, nonce,
			                                    display, prompt, maxAge, uiLocales, claimsLocales, 
			                                    idTokenHint, loginHint, acrValues, claims, requestObject);
	
		// Request object by URL reference
		if (requestURI != null)
			return new AuthenticationRequest(uri, rt, scope, clientID, redirectURI, state, nonce,
			                                    display, prompt, maxAge, uiLocales, claimsLocales, 
			                                    idTokenHint, loginHint, acrValues, claims, requestURI);
		
		// No request object or URI
		return new AuthenticationRequest(uri, rt, scope, clientID, redirectURI, state, nonce,
			                            display, prompt, maxAge, uiLocales, claimsLocales, 
			                            idTokenHint, loginHint, acrValues, claims);
	}
	
	
	/**
	 * Parses an OpenID Connect authentication request from the specified
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
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an 
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final String query)
		throws ParseException {
	
		return parse(null, URLUtils.parseParameters(query));
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
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
	 * @param uri   The URI of the OAuth 2.0 authorisation endpoint. May be
	 *              {@code null} if the {@link #toHTTPRequest} method will
	 *              not be used.
	 * @param query The URL query string. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final URL uri, final String query)
		throws ParseException {

		return parse(uri, URLUtils.parseParameters(query));
	}
	
	
	/**
	 * Parses an authentication request from the specified HTTP GET or HTTP
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
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an 
	 *                        OpenID Connect authentication request.
	 */
	public static AuthorizationRequest parse(final HTTPRequest httpRequest) 
		throws ParseException {
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing URL query string");
		
		return parse(httpRequest.getURL(), query);
	}
}
