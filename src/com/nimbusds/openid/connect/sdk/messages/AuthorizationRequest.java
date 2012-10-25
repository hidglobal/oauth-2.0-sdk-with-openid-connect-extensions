package com.nimbusds.openid.connect.sdk.messages;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.JOSEObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.claims.ClientID;

import com.nimbusds.openid.connect.sdk.http.HTTPRequest;

import com.nimbusds.openid.connect.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.util.URLUtils;


/**
 * Authorisation request. Used to authenticate an end-user and request her 
 * authorisation to release information to the client. This class is immutable.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * https://server.example.com/op/authorize?
 * response_type=code%20id_token
 * &client_id=s6BhdRkqt3
 * &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * &scope=openid
 * &nonce=n-0S6_WzA2Mj
 * &state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.
 *     <li>OpenID Connect Standard 1.0, section 2.3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-22)
 */
public final class AuthorizationRequest implements Request {


	/**
	 * The response type set (required).
	 */
	private final ResponseTypeSet rts;
	
	
	/**
	 * The scope (required).
	 */
	private final Scope scope;
	
	
	/**
	 * The client identifier (required).
	 */
	private final ClientID clientID;
	
	
	/**
	 * The redirection URI where the response will be sent (required). 
	 */
	private final URL redirectURI;
	
	
	/**
	 * The nonce (required for implicit flow, optional for code flow).
	 */
	private final Nonce nonce;
	
	
	/**
	 * The opaque value to maintain state between the request and the 
	 * callback (recommended).
	 */
	private final State state;
	
	
	/**
	 * The requested display type (optional).
	 */
	private final Display display;
	
	
	/**
	 * The requested prompt (optional).
	 */
	private final Prompt prompt;
	
	
	/**
	 * OpenID request object as plain or signed JOSE object (optional).
	 */
	private final JOSEObject requestObj;
	
	
	/**
	 * An URL that points to an OpenID request object (optional).
	 */
	private final URL requestURI;
	
	
	/**
	 * An ID Token passed as a hint about the user's current or past 
	 * authenticated session with the client (optional). Should be present 
	 * if {@code prompt=none} is sent.
	 */
	private final JWT idTokenHint;
	
	
	/**
	 * Creates a new minimal authorisation request.
	 *
	 * @param rts         The response type set. Corresponds to the 
	 *                    {@code response_type} parameter. Must not be
	 *                    {@code null}.
	 * @param scope       The UserInfo request scope. Corresponds to the
	 *                    {@code scope} parameter. Must not be {@code null}.
	 * @param clientID    The client identifier. Corresponds to the
	 *                    {@code client_id} parameter. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The redirection URI. Corresponds to the
	 *                    {@code redirect_uri} parameter. Must not be 
	 *                    {@code null}.
	 * @param nonce       The nonce. Corresponds to the {@code nonce} 
	 *                    parameter. May be {@code null} for code flow.
	 */
	public AuthorizationRequest(final ResponseTypeSet rts,
	                            final Scope scope,
				    final ClientID clientID,
				    final URL redirectURI,
				    final Nonce nonce) {

		// Nulls: state, display, prompt, idTokenHint
		this(rts, scope, clientID, redirectURI, nonce, 
		     null, null, null, null);
	}
	
	
	/**
	 * Creates a new authorisation request without an OpenID Connect request 
	 * object.
	 *
	 * @param rts         The response type set. Corresponds to the 
	 *                    {@code response_type} parameter. Must not be
	 *                    {@code null}.
	 * @param scope       The UserInfo request scope. Corresponds to the
	 *                    {@code scope} parameter. Must not be {@code null}.
	 * @param clientID    The client identifier. Corresponds to the
	 *                    {@code client_id} parameter. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The redirection URI. Corresponds to the
	 *                    {@code redirect_uri} parameter. Must not be 
	 *                    {@code null}.
	 * @param nonce       The nonce. Corresponds to the {@code nonce} 
	 *                    parameter. May be {@code null} for code flow.
	 * @param state       The state. Corresponds to the recommended 
	 *                    {@code state} parameter. {@code null} if not 
	 *                    specified.
	 * @param display     The requested display type. Corresponds to the 
	 *                    optional {@code display} parameter. {@code null} 
	 *                    if not specified.
	 * @param prompt      The requested prompt. Corresponds to the optional 
	 *                    {@code prompt} parameter. {@code null} if not 
	 *                    specified.
	 * @param idTokenHint The ID Token hint. Corresponds to the optinal 
	 *                    {@code id_token_hint} parameter. {@code null} if
	 *                    not specified.
	 */
	public AuthorizationRequest(final ResponseTypeSet rts,
	                            final Scope scope,
				    final ClientID clientID,
				    final URL redirectURI,
				    final Nonce nonce,
				    final State state,
				    final Display display,
				    final Prompt prompt,
				    final JWT idTokenHint) {
				    
				    
		this(rts, scope, clientID, redirectURI, nonce, 
		     state, display, prompt, (JOSEObject)null, idTokenHint);    
	}
	
	
	/**
	 * Creates a new authorisation request with an OpenID Connect request 
	 * object specified as direct parameter.
	 *
	 * @param rts         The response type set. Corresponds to the 
	 *                    {@code response_type} parameter. Must not be
	 *                    {@code null}.
	 * @param scope       The UserInfo request scope. Corresponds to the
	 *                    {@code scope} parameter. Must not be {@code null}.
	 * @param clientID    The client identifier. Corresponds to the
	 *                    {@code client_id} parameter. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The redirection URI. Corresponds to the
	 *                    {@code redirect_uri} parameter. Must not be 
	 *                    {@code null}.
	 * @param nonce       The nonce. Corresponds to the {@code nonce} 
	 *                    parameter. May be {@code null} for code flow.
	 * @param state       The state. Corresponds to the recommended 
	 *                    {@code state} parameter. {@code null} if not 
	 *                    specified.
	 * @param display     The requested display type. Corresponds to the 
	 *                    optional {@code display} parameter. {@code null} 
	 *                    if not specified.
	 * @param prompt      The requested prompt. Corresponds to the optional 
	 *                    {@code prompt} parameter. {@code null} if not 
	 *                    specified.
	 * @param requestObj  The OpenID Connect request object. Corresponds to 
	 *                    the optional {@code request} parameter. 
	 *                    {@code null} if not specified.
	 * @param idTokenHint The ID Token hint. Corresponds to the optinal 
	 *                    {@code id_token_hint} parameter. {@code null} if
	 *                    not specified.
	 */
	public AuthorizationRequest(final ResponseTypeSet rts,
	                            final Scope scope,
				    final ClientID clientID,
				    final URL redirectURI,
				    final Nonce nonce,
				    final State state,
				    final Display display,
				    final Prompt prompt,
				    final JOSEObject requestObj,
				    final JWT idTokenHint) {
				    
		if (rts == null)
			throw new IllegalArgumentException("The response type set must not be null");
		
		this.rts = rts;
		
		
		if (scope == null)
			throw new IllegalArgumentException("The UserInfo scope must not be null");
		
		this.scope = scope;
		
		
		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");
			
		this.clientID = clientID;
		
		
		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
			
		this.redirectURI = redirectURI;
		
		
		// Nonce required for implicit protocol flow
		if (rts.impliesImplicitFlow() && nonce == null)
			throw new IllegalArgumentException("Nonce is required in implicit protocol flow");
		
		this.nonce = nonce;
		
		// Optional parameters
		this.state = state;
		this.display = display;
		this.prompt = prompt;
		this.requestObj = requestObj;
		this.requestURI = null;
		this.idTokenHint = idTokenHint;
	}
	
	
	/**
	 * Creates a new authorisation request with an OpenID Connect request 
	 * object referenced by URI.
	 *
	 * @param rts         The response type set. Corresponds to the 
	 *                    {@code response_type} parameter. Must not be
	 *                    {@code null}.
	 * @param scope       The UserInfo request scope. Corresponds to the
	 *                    {@code scope} parameter. Must not be {@code null}.
	 * @param clientID    The client identifier. Corresponds to the
	 *                    {@code client_id} parameter. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The redirection URI. Corresponds to the
	 *                    {@code redirect_uri} parameter. Must not be 
	 *                    {@code null}.
	 * @param nonce       The nonce. Corresponds to the {@code nonce} 
	 *                    parameter. May be {@code null} for code flow.
	 * @param state       The state. Corresponds to the recommended 
	 *                    {@code state} parameter. {@code null} if not 
	 *                    specified.
	 * @param display     The requested display type. Corresponds to the 
	 *                    optional {@code display} parameter. {@code null} 
	 *                    if not specified.
	 * @param prompt      The requested prompt. Corresponds to the optional 
	 *                    {@code prompt} parameter. {@code null} if not 
	 *                    specified.
	 * @param requestURI  The OpenID Connect request object URI. Corresponds
	 *                    to the optional {@code request_uri} parameter.
	 *                    {@code null} if not specified.
	 * @param idTokenHint The ID Token hint. Corresponds to the optinal 
	 *                    {@code id_token_hint} parameter. {@code null} if
	 *                    not specified.
	 */
	public AuthorizationRequest(final ResponseTypeSet rts,
	                            final Scope scope,
				    final ClientID clientID,
				    final URL redirectURI,
				    final Nonce nonce,
				    final State state,
				    final Display display,
				    final Prompt prompt,
				    final URL requestURI,
				    final JWT idTokenHint) {
				    
		if (rts == null)
			throw new IllegalArgumentException("The response type set must not be null");
		
		this.rts = rts;
		
		
		if (scope == null)
			throw new IllegalArgumentException("The UserInfo scope must not be null");
		
		this.scope = scope;
		
		
		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");
			
		this.clientID = clientID;
		
		
		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
			
		this.redirectURI = redirectURI;
		
		
		// Nonce required for implicit protocol flow
		if (rts.impliesImplicitFlow() && nonce == null)
			throw new IllegalArgumentException("Nonce is required in implicit protocol flow");
		
		this.nonce = nonce;
		
		// Optional parameters
		this.state = state;
		this.display = display;
		this.prompt = prompt;
		this.requestObj = null;
		this.requestURI = requestURI;
		this.idTokenHint = idTokenHint;
	}
	
	
	
	/**
	 * Gets the response type set. Corresponds to the {@code response_type}
	 * parameter.
	 *
	 * @return The response type set.
	 */
	public ResponseTypeSet getResponseTypeSet() {
	
		return rts;
	}
	
	
	/**
	 * Gets the UserInfo request scope. Corresponds to the {@code scope} 
	 * parameter.
	 *
	 * @return The UserInfo request scope.
	 */
	public Scope getScope() {
	
		return scope;
	}
	
	
	/**
	 * Gets the client identifier. Corresponds to the {@code client_id} 
	 * parameter.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {
	
		return clientID;
	}
	
	
	/**
	 * Gets the redirection URI. Corresponds to the {@code redirection_uri}
	 * parameter.
	 *
	 * @return The redirection URI.
	 */
	public URL getRedirectURI() {
	
		return redirectURI;
	}
	
	
	/**
	 * Gets the nonce. Corresponds to the {@code nonce} parameter.
	 *
	 * @return The nonce, {@code null} if not specified.
	 */
	public Nonce getNonce() {
	
		return nonce;
	}
	
	
	/**
	 * Gets the state. Corresponds to the recommended {@code state} 
	 * parameter.
	 *
	 * @return The state, {@code null} if not specified.
	 */
	public State getState() {
	
		return state;
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
	 * Gets the requested prompt. Corresponds to the optional {@code prompt}
	 * parameter.
	 *
	 * @return The requested prompt, {@code null} if not specified.
	 */
	public Prompt getPrompt() {
	
		return prompt;
	}
	
	
	/**
	 * Gets the JOSE-encoded OpenID request object. Corresponds to the
	 * optional {@code request} parameter.
	 *
	 * @return The request object, {@code null} if not specified.
	 */
	public JOSEObject getRequestObject() {
	
		return requestObj;
	}
	
	
	/**
	 * Gets the URI that points to an OpenID request object. Corresponds to
	 * the optional {@code request_uri} parameter.
	 *
	 * @return The OpenID request object URI, {@code null} if not specified.
	 */
	public URL getRequestObjectURI() {
	
		return requestURI;
	}
	
	
	/**
	 * Returns {@code true} if this authorisation request has an OpenID
	 * Request Object (included in the {@code request} parameter or
	 * referenced through the {@code request_uri} parameter).
	 *
	 * @return {@code true} if a request object is specified, else 
	 *         {@code false}.
	 */
	public boolean hasRequestObject() {
	
		if (requestObj != null || requestURI != null)
			return true;
		else
			return false;
	}
	
	
	/**
	 * Gets the ID Token hint. Corresponds to the {@code id_token_hint}
	 * parameter.
	 *
	 * @return The ID Token hint, {@code null} if not specified.
	 */
	public JWT getIDTokenHint() {
	
		return idTokenHint;
	}
	
	
	/**
	 * Returns the URL query string for this authorisation request.
	 *
	 * <p>Note that the '?' character preceding the query string in an URL
	 * is not included in the returned string.
	 *
	 * <p>Example URL query string:
	 *
	 * <pre>
	 * response_type=token%20id_token
	 * &client_id=s6BhdRkqt3
	 * &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &scope=openid%20profile
	 * &state=af0ifjsldkj
	 * &nonce=n-0S6_WzA2Mj
	 * </pre>
	 * 
	 * @return The URL query string.
	 *
	 * @throws SerializeException If this authorisation request couldn't be
	 *                            serialised to an URL query string.
	 */
	public String toQueryString()
		throws SerializeException {
		
		Map <String,String> params = new LinkedHashMap<String,String>();
		
		params.put("response_type", rts.toString());
		params.put("client_id", clientID.getClaimValue());
		params.put("scope", scope.toString());
		params.put("redirect_uri", redirectURI.toString());
		
		if (nonce != null)
			params.put("nonce", nonce.toString());
		
		if (state != null)
			params.put("state", state.toString());
		
		if (display != null)
			params.put("display", display.toString());
		
		if (prompt != null)
			params.put("prompt", prompt.toString());
		
		
		// Checks request exor request_uri done by setter methods
		
		if (requestObj != null) {
		
			try {
				params.put("request", requestObj.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize request object: " + e.getMessage());
			}
		}
		
		if (requestURI != null)
			params.put("request_uri", requestURI.toString());
		
		if (idTokenHint != null) {
		
			try {
				params.put("id_token_hint", idTokenHint.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize ID token hint: " + e.getMessage());
			}
		}
		
		return URLUtils.serializeParameters(params);
	}
	
	
	/**
	 * Returns the matching HTTP request.
	 *
	 * @param method The HTTP request method. If {@code null} assumes the
	 *               default HTTP GET.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the OpenID Connect request message
	 *                            couldn't be serialised to an HTTP request.
	 */
	public HTTPRequest toHTTPRequest(final HTTPRequest.Method method) 
		throws SerializeException {
		
		HTTPRequest httpRequest;
		
		if (method == null || method == HTTPRequest.Method.GET)
			httpRequest = new HTTPRequest(HTTPRequest.Method.GET);
		else
			httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		
		httpRequest.setQuery(toQueryString());
		
		return httpRequest;
	}
	
	
	/**
	 * Returns the matching HTTP GET request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the OpenID Connect request message
	 *                            couldn't be serialised to an HTTP GET 
	 *                            request.
	 */
	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
	
		return toHTTPRequest(HTTPRequest.Method.GET);
	}
	
	
	/**
	 * Parses an authorisation request from the specified URL query string.
	 *
	 * <p>Example URL query string:
	 *
	 * <pre>
	 * response_type=token%20id_token
	 * &client_id=s6BhdRkqt3
	 * &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &scope=openid%20profile
	 * &state=af0ifjsldkj
	 * &nonce=n-0S6_WzA2Mj
	 * </pre>
	 *
	 * @param query The URL query string. Must not be {@code null}.
	 *
	 * @return The parsed authorisation request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to a 
	 *                        valid authorisation request.
	 */
	public static AuthorizationRequest parse(final String query)
		throws ParseException {
	
		Map <String,String> params = URLUtils.parseParameters(query);
		
		String v = null;
		
		// Mandatory params
		
		v = params.get("response_type");
		
		if (StringUtils.isUndefined(v))
			throw new ParseException("Missing \"response_type\" parameter");
		
		ResponseTypeSet rts = null;
		
		try {
			rts = ResponseTypeSet.parse(v);
		
		} catch (ParseException e) {
			
			throw new ParseException("Invalid \"response_type\" parameter: " + e.getMessage(), e);
		}
			
		v = params.get("scope");
		
		if (StringUtils.isUndefined(v))
			throw new ParseException("Missing \"scope\" parameter");
		
		Scope scope = null;
		
		try {
			scope = Scope.parseStrict(v);
			
		} catch (ParseException e) {
		
			throw new ParseException("Invalid \"scope\" parameter: " + e.getMessage(), e);
		}
		
		
		v = params.get("client_id");
		
		if (StringUtils.isUndefined(v))
			throw new ParseException("Missing \"client_id\" parameter");
		
		ClientID clientID = new ClientID();
		clientID.setClaimValue(v);
		
		
		v = params.get("redirect_uri");
		
		if (StringUtils.isUndefined(v))
			throw new ParseException("Missing \"redirect_uri\" parameter");
			
		URL redirectURI = null;
		
		try {
			redirectURI = new URL(v);
			
		} catch (MalformedURLException e) {
		
			throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), e);
		}
		
		
		Nonce nonce = Nonce.parse(params.get("nonce"));
		
		// Nonce required in implicit flow
		if (rts.impliesImplicitFlow() && nonce == null)
			throw new ParseException("Missing \"nonce\" parameter");
		
		
		// Optional params
		
		State state = State.parse(params.get("state"));
		
		
		Display display = null;
		
		try {
			display = Display.parse(params.get("display"));

		} catch (ParseException e) {

			throw new ParseException("Invalid \"display\" parameter: " + e.getMessage(), e);
		}
		
		
		Prompt prompt = null;
		
		try {
			prompt = Prompt.parse(params.get("prompt"));
				
		} catch (ParseException e) {
			
			throw new ParseException("Invalid \"prompt\" parameter: " + e.getMessage(), e);
		}
		
		
		v = params.get("request");
		
		JOSEObject requestObj = null;
		
		if (StringUtils.isDefined(v)) {
		
			try {
				requestObj = JOSEObject.parse(v);
				
			} catch (java.text.ParseException e) {
			
				throw new ParseException("Invalid \"request\" parameter: " + e.getMessage(), e);
			}
		}
		
		
		v = params.get("request_uri");
		
		URL requestURI = null;
		
		if (StringUtils.isDefined(v)) {
	
			// request_object and request_uri must not be defined at the same time
			if (requestObj != null)
				throw new ParseException("Invalid request: Found mutually exclusive \"request_object\" and \"request_uri\" parameters");
	
			try {
				requestURI = new URL(v);
		
			} catch (MalformedURLException e) {
			
				throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), e);
			}
		}
		
		
		v = params.get("id_token_hint");
		
		JWT idTokenHint = null;
		
		if (StringUtils.isDefined(v)) {
		
			try {
				idTokenHint = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
		
				throw new ParseException("Invalid \"id_token_hint\" parameter: " + e.getMessage(), e);
			}
		}
		
	
		// Select appropriate constructor
		
		// Inline request object
		if (requestObj != null)
			return new AuthorizationRequest(rts, scope, clientID, redirectURI, nonce,
			                                state, display, prompt, requestObj, idTokenHint);
	
		// Request object by URL reference
		if (requestURI != null)
			return new AuthorizationRequest(rts, scope, clientID, redirectURI, nonce,
			                                state, display, prompt, requestURI, idTokenHint);
		
		// No request object or URI
		return new AuthorizationRequest(rts, scope, clientID, redirectURI, nonce,
		                                state, display, prompt, idTokenHint);
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
	 * &client_id=s6BhdRkqt3
	 * &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &scope=openid
	 * &nonce=n-0S6_WzA2Mj
	 * &state=af0ifjsldkj
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The parsed authorisation request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        valid authorisation request.
	 */
	public static AuthorizationRequest parse(final HTTPRequest httpRequest) 
		throws ParseException {
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing URL query string");
		
		return parse(query);
	}
}
