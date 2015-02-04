package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.net.URISyntaxException;
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
import com.nimbusds.oauth2.sdk.util.URIUtils;
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
public class AuthenticationRequest extends AuthorizationRequest {
	
	
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
	 * Request object URI (optional).
	 */
	private final URI requestURI;


	/**
	 * Builder for constructing OpenID Connect authentication requests.
	 */
	public static class Builder {


		/**
		 * The endpoint URI (optional).
		 */
		private URI uri;


		/**
		 * The response type (required).
		 */
		private final ResponseType rt;


		/**
		 * The client identifier (required).
		 */
		private final ClientID clientID;


		/**
		 * The redirection URI where the response will be sent
		 * (required).
		 */
		private final URI redirectURI;


		/**
		 * The scope (required).
		 */
		private final Scope scope;


		/**
		 * The opaque value to maintain state between the request and
		 * the callback (recommended).
		 */
		private State state;


		/**
		 * The nonce (required for implicit flow, optional for code
		 * flow).
		 */
		private Nonce nonce;


		/**
		 * The requested display type (optional).
		 */
		private Display display;


		/**
		 * The requested prompt (optional).
		 */
		private Prompt prompt;


		/**
		 * The required maximum authentication age, in seconds, 0 if
		 * not specified (optional).
		 */
		private int maxAge;


		/**
		 * The end-user's preferred languages and scripts for the user
		 * interface (optional).
		 */
		private List<LangTag> uiLocales;


		/**
		 * The end-user's preferred languages and scripts for claims
		 * being returned (optional).
		 */
		private List<LangTag> claimsLocales;


		/**
		 * Previously issued ID Token passed to the authorisation
		 * server as a hint about the end-user's current or past
		 * authenticated session with the client (optional). Should be
		 * present when {@code prompt=none} is used.
		 */
		private JWT idTokenHint;


		/**
		 * Hint to the authorisation server about the login identifier
		 * the end-user may use to log in (optional).
		 */
		private String loginHint;


		/**
		 * Requested Authentication Context Class Reference values
		 * (optional).
		 */
		private List<ACR> acrValues;


		/**
		 * Individual claims to be returned (optional).
		 */
		private ClaimsRequest claims;


		/**
		 * Request object (optional).
		 */
		private JWT requestObject;


		/**
		 * Request object URI (optional).
		 */
		private URI requestURI;


		/**
		 * Creates a new OpenID Connect authentication request builder.
		 *
		 * @param rt          The response type. Corresponds to the
		 *                    {@code response_type} parameter. Must
		 *                    specify a valid OpenID Connect response
		 *                    type. Must not be {@code null}.
		 * @param scope       The request scope. Corresponds to the
		 *                    {@code scope} parameter. Must contain an
		 *                    {@link OIDCScopeValue#OPENID openid
		 *                    value}. Must not be {@code null}.
		 * @param clientID    The client identifier. Corresponds to the
		 *                    {@code client_id} parameter. Must not be
		 *                    {@code null}.
		 * @param redirectURI The redirection URI. Corresponds to the
		 *                    {@code redirect_uri} parameter. Must not
		 *                    be {@code null}.
		 */
		public Builder(final ResponseType rt,
			       final Scope scope,
			       final ClientID clientID,
			       final URI redirectURI) {

			if (rt == null)
				throw new IllegalArgumentException("The response type must not be null");

			OIDCResponseTypeValidator.validate(rt);

			this.rt = rt;

			if (scope == null)
				throw new IllegalArgumentException("The scope must not be null");

			if (! scope.contains(OIDCScopeValue.OPENID))
				throw new IllegalArgumentException("The scope must include an \"openid\" value");

			this.scope = scope;

			if (clientID == null)
				throw new IllegalArgumentException("The client ID must not be null");

			this.clientID = clientID;

			if (redirectURI == null)
				throw new IllegalArgumentException("The redirection URI must not be null");

			this.redirectURI = redirectURI;
		}


		/**
		 * Sets the state. Corresponds to the recommended {@code state}
		 * parameter.
		 *
		 * @param state The state, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder state(final State state) {

			this.state = state;
			return this;
		}


		/**
		 * Sets the URI of the endpoint (HTTP or HTTPS) for which the
		 * request is intended.
		 *
		 * @param uri The endpoint URI, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder endpointURI(final URI uri) {

			this.uri = uri;
			return this;
		}


		/**
		 * Sets the nonce. Corresponds to the conditionally optional
		 * {@code nonce} parameter.
		 *
		 * @param nonce The nonce, {@code null} if not specified.
		 */
		public Builder nonce(final Nonce nonce) {

			this.nonce = nonce;
			return this;
		}


		/**
		 * Sets the requested display type. Corresponds to the optional
		 * {@code display} parameter.
		 *
		 * @param display The requested display type, {@code null} if
		 *                not specified.
		 */
		public Builder display(final Display display) {

			this.display = display;
			return this;
		}


		/**
		 * Sets the requested prompt. Corresponds to the optional
		 * {@code prompt} parameter.
		 *
		 * @param prompt The requested prompt, {@code null} if not
		 *               specified.
		 */
		public Builder prompt(final Prompt prompt) {

			this.prompt = prompt;
			return this;
		}


		/**
		 * Sets the required maximum authentication age. Corresponds to
		 * the optional {@code max_age} parameter.
		 *
		 * @param maxAge The maximum authentication age, in seconds; 0
		 *               if not specified.
		 */
		public Builder maxAge(final int maxAge) {

			this.maxAge = maxAge;
			return this;
		}


		/**
		 * Sets the end-user's preferred languages and scripts for the
		 * user interface, ordered by preference. Corresponds to the
		 * optional {@code ui_locales} parameter.
		 *
		 * @param uiLocales The preferred UI locales, {@code null} if
		 *                  not specified.
		 */
		public Builder uiLocales(final List<LangTag> uiLocales) {

			this.uiLocales = uiLocales;
			return this;
		}


		/**
		 * Sets the end-user's preferred languages and scripts for the
		 * claims being returned, ordered by preference. Corresponds to
		 * the optional {@code claims_locales} parameter.
		 *
		 * @param claimsLocales The preferred claims locales,
		 *                      {@code null} if not specified.
		 */
		public Builder claimsLocales(final List<LangTag> claimsLocales) {

			this.claimsLocales = claimsLocales;
			return this;
		}


		/**
		 * Sets the ID Token hint. Corresponds to the conditionally
		 * optional {@code id_token_hint} parameter.
		 *
		 * @param idTokenHint The ID Token hint, {@code null} if not
		 *                    specified.
		 */
		public Builder idTokenHint(final JWT idTokenHint) {

			this.idTokenHint = idTokenHint;
			return this;
		}


		/**
		 * Sets the login hint. Corresponds to the optional
		 * {@code login_hint} parameter.
		 *
		 * @param loginHint The login hint, {@code null} if not
		 *                  specified.
		 */
		public Builder loginHint(final String loginHint) {

			this.loginHint = loginHint;
			return this;
		}


		/**
		 * Sets the requested Authentication Context Class Reference
		 * values. Corresponds to the optional {@code acr_values}
		 * parameter.
		 *
		 * @param acrValues The requested ACR values, {@code null} if
		 *                  not specified.
		 */
		public Builder acrValues(final List<ACR> acrValues) {

			this.acrValues = acrValues;
			return this;
		}


		/**
		 * Sets the individual claims to be returned. Corresponds to
		 * the optional {@code claims} parameter.
		 *
		 * @param claims The individual claims to be returned,
		 *               {@code null} if not specified.
		 */
		public Builder claims(final ClaimsRequest claims) {

			this.claims = claims;
			return this;
		}


		/**
		 * Sets the request object. Corresponds to the optional
		 * {@code request} parameter. Must not be specified together
		 * with a request object URI.
		 *
		 * @return The request object, {@code null} if not specified.
		 */
		public Builder requestObject(final JWT requestObject) {

			this.requestObject = requestObject;
			return this;
		}


		/**
		 * Sets the request object URI. Corresponds to the optional
		 * {@code request_uri} parameter. Must not be specified
		 * together with a request object.
		 *
		 * @param requestURI The request object URI, {@code null} if
		 *                   not specified.
		 */
		public Builder requestURI(final URI requestURI) {

			this.requestURI = requestURI;
			return this;
		}


		/**
		 * Builds a new authentication request.
		 *
		 * @return The authentication request.
		 */
		public AuthenticationRequest build() {

			try {
				return new AuthenticationRequest(
					uri, rt, scope, clientID, redirectURI, state, nonce,
					display, prompt, maxAge, uiLocales, claimsLocales,
					idTokenHint, loginHint, acrValues, claims,
					requestObject, requestURI);

			} catch (IllegalArgumentException e) {

				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}
	
	
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
	public AuthenticationRequest(final URI uri,
				     final ResponseType rt,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
				     final State state,
				     final Nonce nonce) {

		// Not specified: display, prompt, maxAge, uiLocales, claimsLocales, 
		// idTokenHint, loginHint, acrValues, claims
		this(uri, rt, scope, clientID, redirectURI, state, nonce, 
		     null, null, 0, null, null, 
		     null, null, null, null, null, null);
	}
	
	
	/**
	 * Creates a new OpenID Connect authentication request.
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
	 *                      {@code request} parameter. Must not be
	 *                      specified together with a request object URI.
	 *                      {@code null} if not specified.
	 * @param requestURI    The request object URI. Corresponds to the
	 *                      optional {@code request_uri} parameter. Must
	 *                      not be specified together with a request
	 *                      object. {@code null} if not specified.
	 */
	public AuthenticationRequest(final URI uri,
				     final ResponseType rt,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
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
				     final JWT requestObject,
				     final URI requestURI) {
				    
		super(uri, rt, clientID, redirectURI, scope, state);

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirection URI must not be null");
		
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

		if (requestObject != null && requestURI != null)
			throw new IllegalArgumentException("Either a request object or a request URI must be specified, but not both");

		this.requestObject = requestObject;
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
	 * Gets the request object URI. Corresponds to the optional
	 * {@code request_uri} parameter.
	 *
	 * @return The request object URI, {@code null} if not specified.
	 */
	public URI getRequestURI() {
	
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
	
		return requestObject != null || requestURI != null;
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
	public static AuthenticationRequest parse(final URI uri, final Map<String,String> params)
		throws ParseException {

		// Parse and validate the core OAuth 2.0 autz request params in 
		// the context of OIDC
		AuthorizationRequest ar = AuthorizationRequest.parse(uri, params);

		ClientID clientID = ar.getClientID();
		State state = ar.getState();

		// Required in OIDC
		URI redirectURI = ar.getRedirectionURI();

		if (redirectURI == null) {
			String msg = "Missing \"redirect_uri\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, null, state);
		}


		ResponseType rt = ar.getResponseType();
		
		try {
			OIDCResponseTypeValidator.validate(rt);
			
		} catch (IllegalArgumentException e) {
			String msg = "Unsupported \"response_type\" parameter: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.appendDescription(": " + msg),
					         clientID, redirectURI, state);
		}
		
		// Required in OIDC, must include "openid" parameter
		Scope scope = ar.getScope();

		if (scope == null) {
			String msg = "Missing \"scope\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, state);
		}

		if (! scope.contains(OIDCScopeValue.OPENID)) {
			String msg = "The scope must include an \"openid\" value";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, state);
		}


		// Parse the remaining OIDC parameters
		Nonce nonce = Nonce.parse(params.get("nonce"));
		
		// Nonce required in implicit flow
		if (rt.impliesImplicitFlow() && nonce == null) {
			String msg = "Missing \"nonce\" parameter: Required in implicit flow";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, state);
		}
		
		Display display;
		
		try {
			display = Display.parse(params.get("display"));

		} catch (ParseException e) {
			String msg = "Invalid \"display\" parameter: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, state, e);
		}
		
		
		Prompt prompt;
		
		try {
			prompt = Prompt.parse(params.get("prompt"));
				
		} catch (ParseException e) {
			String msg = "Invalid \"prompt\" parameter: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, state, e);
		}


		String v = params.get("max_age");

		int maxAge = 0;

		if (StringUtils.isNotBlank(v)) {

			try {
				maxAge = Integer.parseInt(v);

			} catch (NumberFormatException e) {
				String msg = "Invalid \"max_age\" parameter: " + v;
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, state, e);
			}
		}


		v = params.get("ui_locales");

		List<LangTag> uiLocales = null;

		if (StringUtils.isNotBlank(v)) {

			uiLocales = new LinkedList<>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				try {
					uiLocales.add(LangTag.parse(st.nextToken()));

				} catch (LangTagException e) {
					String msg = "Invalid \"ui_locales\" parameter: " + e.getMessage();
					throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
						                 clientID, redirectURI, state, e);
				}
			}
		}


		v = params.get("claims_locales");

		List<LangTag> claimsLocales = null;

		if (StringUtils.isNotBlank(v)) {

			claimsLocales = new LinkedList<>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				try {
					claimsLocales.add(LangTag.parse(st.nextToken()));

				} catch (LangTagException e) {
					String msg = "Invalid \"claims_locales\" parameter: " + e.getMessage();
					throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
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
				String msg = "Invalid \"id_token_hint\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, state, e);
			}
		}

		String loginHint = params.get("login_hint");


		v = params.get("acr_values");

		List<ACR> acrValues = null;

		if (StringUtils.isNotBlank(v)) {

			acrValues = new LinkedList<>();

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
				String msg = "Invalid \"claims\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, state, e);
			}

			// Parse exceptions silently ignored
			claims = ClaimsRequest.parse(jsonObject);
		}
		
		
		v = params.get("request_uri");
		
		URI requestURI = null;
		
		if (StringUtils.isNotBlank(v)) {

			try {
				requestURI = new URI(v);
		
			} catch (URISyntaxException e) {
				String msg = "Invalid \"request_uri\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, state, e);
			}
		}

		v = params.get("request");

		JWT requestObject = null;

		if (StringUtils.isNotBlank(v)) {

			// request_object and request_uri must not be defined at the same time
			if (requestURI != null) {
				String msg = "Invalid request: Found mutually exclusive \"request\" and \"request_uri\" parameters";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, state, null);
			}

			try {
				requestObject = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
				String msg = "Invalid \"request_object\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, state, e);
			}
		}
		
		
		return new AuthenticationRequest(
			uri, rt, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, requestObject, requestURI);
	}
	
	
	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * URI query string.
	 *
	 * <p>Example URI query string:
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
	 * @param query The URI query string. Must not be {@code null}.
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
	 * URI query string.
	 *
	 * <p>Example URI query string:
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
	 * @param query The URI query string. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final URI uri, final String query)
		throws ParseException {

		return parse(uri, URLUtils.parseParameters(query));
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * URI.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://server.example.com/authorize?
	 * response_type=token%20id_token
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &amp;scope=openid%20profile
	 * &amp;state=af0ifjsldkj
	 * &amp;nonce=n-0S6_WzA2Mj
	 * </pre>
	 *
	 * @param uri The URI. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), URLUtils.parseParameters(uri.getQuery()));
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
	public static AuthenticationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing URI query string");

		URI endpointURI;

		try {
			endpointURI = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}
		
		return parse(endpointURI, query);
	}
}
