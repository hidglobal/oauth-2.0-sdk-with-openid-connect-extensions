package com.nimbusds.openid.connect.sdk;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JOSEObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseTypeSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.ScopeToken;
import com.nimbusds.oauth2.sdk.SerializeException;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


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
 * @version $version$ (2013-01-21)
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
	 * Optional hint to the authorisation service as to the login 
	 * identifier the user may use to authenticate at the authorisation 
	 * service (if necessary). This hint can be used by an RP if it first 
	 * asks the user for their email address (or other identifier) and then
	 * wants to pass that value as a hint to the discovered authorisation
	 * service. It is recommended that the hint value match the value used
	 * for discovery. The use of this parameter is up to the OP's
	 * discretion. 
	 */
	private final String loginHint;
	
	
	/**
	 * Creates a new minimal OpenID Connect authorisation request.
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
	public OIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                final Scope scope,
				        final ClientID clientID,
				        final URL redirectURI,
				        final Nonce nonce) {

		// Nulls: state, display, prompt, idTokenHint, loginHint
		this(rts, scope, clientID, redirectURI, nonce, 
		     null, null, null, null, null);
	}
	
	
	/**
	 * Creates a new OpenID Connect authorisation request without an OpenID
	 * request object.
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
	 * @param idTokenHint The ID Token hint. Corresponds to the optional 
	 *                    {@code id_token_hint} parameter. {@code null} if
	 *                    not specified.
	 * @param loginHint   The login hint. Corresponds to the optional
	 *                    {@code login_hint} parameter. {@code null} if not
	 *                    specified.
	 */
	public OIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                final Scope scope,
				        final ClientID clientID,
				        final URL redirectURI,
				        final Nonce nonce,
				        final State state,
				        final Display display,
				        final Prompt prompt,
				        final JWT idTokenHint,
				        final String loginHint) {
				    
				    
		this(rts, scope, clientID, redirectURI, nonce, 
		     state, display, prompt, (JOSEObject)null, idTokenHint, loginHint);    
	}
	
	
	/**
	 * Creates a new OpenID Connect authorisation request with an OpenID 
	 * request object specified by value.
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
	 * @param requestObj  The OpenID request object. Corresponds to the
	 *                    optional {@code request} parameter. 
	 *                    {@code null} if not specified.
	 * @param idTokenHint The ID Token hint. Corresponds to the optional 
	 *                    {@code id_token_hint} parameter. {@code null} if
	 *                    not specified.
	 * @param loginHint   The login hint. Corresponds to the optional
	 *                    {@code login_hint} parameter. {@code null} if not
	 *                    specified.
	 */
	public OIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                final Scope scope,
				        final ClientID clientID,
				        final URL redirectURI,
				        final Nonce nonce,
				        final State state,
				        final Display display,
				        final Prompt prompt,
				        final JOSEObject requestObj,
				        final JWT idTokenHint,
				        final String loginHint) {
				    
		super(rts, clientID, redirectURI, scope, state);

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");

		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");
		
		
		// Nonce required for implicit protocol flow
		if (rts.impliesImplicitFlow() && nonce == null)
			throw new IllegalArgumentException("Nonce is required in implicit protocol flow");
		
		this.nonce = nonce;
		
		// Optional parameters
		this.display = display;
		this.prompt = prompt;
		this.requestObj = requestObj;
		this.requestURI = null;
		this.idTokenHint = idTokenHint;
		this.loginHint = loginHint;
	}
	
	
	/**
	 * Creates a new OpenID Connect authorisation request with an OpenID 
	 * request object specified by URI reference.
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
	 * @param requestURI  The OpenID request object URI. Corresponds to the
	 *                    optional {@code request_uri} parameter.
	 *                    {@code null} if not specified.
	 * @param idTokenHint The ID Token hint. Corresponds to the optional 
	 *                    {@code id_token_hint} parameter. {@code null} if
	 *                    not specified.
	 * @param loginHint   The login hint. Corresponds to the optional
	 *                    {@code login_hint} parameter. {@code null} if not
	 *                    specified.
	 */
	public OIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                final Scope scope,
				        final ClientID clientID,
				        final URL redirectURI,
				        final Nonce nonce,
				        final State state,
				        final Display display,
				        final Prompt prompt,
				        final URL requestURI,
				        final JWT idTokenHint,
				        final String loginHint) {
				    
		super(rts, clientID, redirectURI, scope, state);

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");

		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");
		
		
		// Nonce required for implicit protocol flow
		if (rts.impliesImplicitFlow() && nonce == null)
			throw new IllegalArgumentException("Nonce is required in implicit protocol flow");
		
		this.nonce = nonce;
		
		// Optional parameters
		this.display = display;
		this.prompt = prompt;
		this.requestObj = null;
		this.requestURI = requestURI;
		this.idTokenHint = idTokenHint;
		this.loginHint = loginHint;
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
	 * Gets the login hint. Corresponds to the {@code login_hint} 
	 * parameter.
	 *
	 * @return The login hint, {@code null} if not specified.
	 */
	public String getLoginHint() {

		return loginHint;
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
		
		
		// Request EXOR request_uri check done by setter methods
		
		if (requestObj != null) {
		
			try {
				params.put("request", requestObj.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize request object: " + e.getMessage(), e);
			}
		}
		
		if (requestURI != null)
			params.put("request_uri", requestURI.toString());
		
		if (idTokenHint != null) {
		
			try {
				params.put("id_token_hint", idTokenHint.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize ID token hint: " + e.getMessage(), e);
			}
		}


		if (loginHint != null)
			params.put("login_hint", loginHint);

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

		if (! scope.contains(new ScopeToken("openid")))
			throw new ParseException("Scope must include \"openid\" token",
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
		
		
		String v = params.get("request");
		
		JOSEObject requestObj = null;
		
		if (StringUtils.isDefined(v)) {
		
			try {
				requestObj = JOSEObject.parse(v);
				
			} catch (java.text.ParseException e) {
			
				throw new ParseException("Invalid \"request\" parameter: " + e.getMessage(), 
					                 OIDCError.INVALID_OPENID_REQUEST_OBJECT,
					                 redirectURI, state, e);
			}
		}
		
		
		v = params.get("request_uri");
		
		URL requestURI = null;
		
		if (StringUtils.isDefined(v)) {
	
			// request_object and request_uri must not be defined at the same time
			if (requestObj != null)
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
		
		
		v = params.get("id_token_hint");
		
		JWT idTokenHint = null;
		
		if (StringUtils.isDefined(v)) {
		
			try {
				idTokenHint = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
		
				throw new ParseException("Invalid \"id_token_hint\" parameter: " + e.getMessage(), 
					                 OAuth2Error.INVALID_REQUEST,
					                 redirectURI, state, e);
			}
		}


		String loginHint = params.get("login_hint");
		
	
		// Select appropriate constructor
		
		// Inline request object
		if (requestObj != null)
			return new OIDCAuthorizationRequest(rts, scope, clientID, redirectURI, nonce,
			                                    state, display, prompt, requestObj, idTokenHint, loginHint);
	
		// Request object by URL reference
		if (requestURI != null)
			return new OIDCAuthorizationRequest(rts, scope, clientID, redirectURI, nonce,
			                                    state, display, prompt, requestURI, idTokenHint, loginHint);
		
		// No request object or URI
		return new OIDCAuthorizationRequest(rts, scope, clientID, redirectURI, nonce,
		                                    state, display, prompt, idTokenHint, loginHint);
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
