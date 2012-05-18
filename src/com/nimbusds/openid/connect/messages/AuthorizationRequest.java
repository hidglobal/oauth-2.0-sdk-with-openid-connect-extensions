package com.nimbusds.openid.connect.messages;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTException;
import com.nimbusds.jwt.SignedJWT;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.claims.ClientID;

import com.nimbusds.openid.connect.http.HTTPRequest;

import com.nimbusds.openid.connect.util.URLUtils;




/**
 * Authorisation request.
 *
 * <p>This class is not thread-safe.
 *
 * <p>Example HTTP request:
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
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-18)
 */
public class AuthorizationRequest implements Request {


	/**
	 * The response type set (required).
	 */
	private ResponseTypeSet responseTypeSet;
	
	
	/**
	 * The scope (required).
	 */
	private Scope scope;
	
	
	/**
	 * The client identifier (required).
	 */
	private ClientID clientID;
	
	
	/**
	 * The redirection URI where the response will be sent (required). 
	 */
	private URL redirectURI;
	
	
	/**
	 * The nonce (required).
	 */
	private Nonce nonce = null;
	
	
	/**
	 * The opaque value to maintain state between the request and the 
	 * callback (recommended).
	 */
	private State state = null;
	
	
	/**
	 * The requested display type (optional).
	 */
	private Display display = null;
	
	
	/**
	 * The requested prompt (optional).
	 */
	private Prompt prompt = null;
	
	
	/**
	 * OpenID request object as JWT (optional).
	 */
	private JWT requestObject = null;
	
	
	/**
	 * An URL that points to an OpenID request object (optional).
	 */
	private URL requestURI = null;
	
	
	/**
	 * The resolved request object, from {@link #requestObject} or 
	 * downloaded from {@link #requestURI}.
	 */
	private JWT resolvedRequestObject = null;
	
	
	/**
	 * The resolved JSON (claims set) of the OpenID request object 
	 * (optional).
	 */
	private JSONObject requestObjectJSON = null;
	
	
	/**
	 * Creates a new minimal authorisation request. Use the setter methods
	 * for the optional request parameters.
	 *
	 * @param rts         The response type set. Corresponds to the 
	 *                    {@code response_type} parameter. Must not be
	 *                    {@code null}.
	 * @param scope       The request scope. Corresponds to the
	 *                    {@code scope} parameter. Must not be {@code null}.
	 * @param clientID    The client identifier. Corresponds to the
	 *                    {@code client_id} parameter. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The redirection URI. Corresponds to the
	 *                    {@code redirect_uri} parameter. Must not be 
	 *                    {@code null}.
	 * @param nonce       The nonce. Corresponds to the {@code nonce} 
	 *                    parameter. Must not be {@code null}.
	 */
	public AuthorizationRequest(final ResponseTypeSet rts,
	                            final Scope scope,
				    final ClientID clientID,
				    final URL redirectURI,
				    final Nonce nonce) {
				    
		setResponseTypeSet(rts);
		setScope(scope);
		setClientID(clientID);
		setRedirectURI(redirectURI);
		setNonce(nonce);   
	}
	
	
	/**
	 * Gets the response type set. Corresponds to the {@code response_type}
	 * parameter.
	 *
	 * @return The response type set.
	 */
	public ResponseTypeSet getResponseTypeSet() {
	
		return responseTypeSet;
	}
	
	
	/**
	 * Gets the resolved response type set.
	 *
	 * <p>The following precendence applies:
	 *
	 * <ol>
	 *     <li>The value from the OpenID request object (if any).
	 *     <li>The value from the main request.
	 * </ol>
	 *
	 * @return The response type set from the OpenID request object (if 
	 *         any), else the response type set from the main request.
	 *
	 * @throws ResolveException If the resolve operation failed.
	 */
	public ResponseTypeSet getResolvedResponseTypeSet()
		throws ResolveException {
	
		if (! this.hasRequestObject())
			return responseTypeSet;
		
		JSONObject o = getResolvedRequestObjectJSON();
		
		if (! o.containsKey("response_type"))
			return responseTypeSet;
		
		Object v = o.get("response_type");
		
		if (v == null || ! (v instanceof String))
			throw new ResolveException("Invalid \"response_type\" parameter: Must be a string and not null");
		
		try {
			return ResponseTypeSet.parse((String)v);
			
		} catch (ParseException e) {
		
			throw new ResolveException("Invalid \"response_type\" parameter: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Sets the response type set. Corresponds to the {@code response_type}
	 * parameter.
	 *
	 * @param rts The response type set. Must not be {@code null}.
	 */
	public void setResponseTypeSet(final ResponseTypeSet rts) {
	
		if (rts == null)
			throw new NullPointerException("The response type set must not be null");
			
		responseTypeSet = rts;
	}
	
	
	/**
	 * Gets the request scope. Corresponds to the {@code scope} parameter.
	 *
	 * @return The request scope.
	 */
	public Scope getScope() {
	
		return scope;
	}
	
	
	/**
	 * Gets the resolved scope.
	 *
	 * <p>The following precendence applies:
	 *
	 * <ol>
	 *     <li>The value from the OpenID request object (if any).
	 *     <li>The value from the main request.
	 * </ol>
	 *
	 * @return The scope from the OpenID request object (if any), else the 
	 *         scope from the main request.
	 *
	 * @throws ResolveException If the resolve operation failed.
	 */
	public Scope getResolvedScope()
		throws ResolveException {
	
		if (! this.hasRequestObject())
			return scope;
		
		JSONObject o = getResolvedRequestObjectJSON();
		
		if (! o.containsKey("scope"))
			return scope;
		
		Object v = o.get("scope");
		
		if (v == null || ! (v instanceof String))
			throw new ResolveException("Invalid \"scope\" parameter: Must be a string and not null");
		
		try {
			return Scope.parseStrict((String)v);
			
		} catch (ParseException e) {
		
			throw new ResolveException("Invalid \"scope\" parameter: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Sets the request scope. Corresponds to the {@code scope} parameter.
	 *
	 * @param scope The request scope. Must not be {@code null}.
	 */
	public void setScope(final Scope scope) {
	
		if (scope == null)
			throw new NullPointerException("The scope must not be null");
		
		this.scope = scope;
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
	 * Gets the resolved client identifier.
	 *
	 * <p>The following precendence applies:
	 *
	 * <ol>
	 *     <li>The value from the OpenID request object (if any).
	 *     <li>The value from the main request.
	 * </ol>
	 *
	 * @return The client identifier from the OpenID request object (if 
	 *         any), else the client identifier from the main request.
	 *
	 * @throws ResolveException If the resolve operation failed.
	 */
	public ClientID getResolvedClientID()
		throws ResolveException {
	
		if (! this.hasRequestObject())
			return clientID;
		
		JSONObject o = getResolvedRequestObjectJSON();
		
		if (! o.containsKey("client_id"))
			return clientID;
		
		Object v = o.get("client_id");
		
		if (v == null || ! (v instanceof String))
			throw new ResolveException("Invalid \"client_id\" parameter: Must be a string and not null");
		
		ClientID cid = new ClientID();
		cid.setClaimValue((String)v);
		return cid;
	}
	
	
	/**
	 * Sets the client identifier. Corresponds to the {@code client_id}
	 * parameter.
	 *
	 * @param clientID The client identifier. Must not be {@code null}.
	 */
	public void setClientID(final ClientID clientID) {
	
		if (clientID == null)
			throw new NullPointerException("The client ID must not be null");
			
		this.clientID = clientID;
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
	 * Gets the resolved redirection URI.
	 *
	 * <p>The following precendence applies:
	 *
	 * <ol>
	 *     <li>The value from the OpenID request object (if any).
	 *     <li>The value from the main request.
	 * </ol>
	 *
	 * @return The redirection URI from the OpenID request object (if any), 
	 *         else the redirection URI from the main request.
	 *
	 * @throws ResolveException If the resolve operation failed.
	 */
	public URL getResolvedRedirectURI()
		throws ResolveException {
	
		if (! this.hasRequestObject())
			return redirectURI;
		
		JSONObject o = getResolvedRequestObjectJSON();
		
		if (! o.containsKey("redirect_uri"))
			return redirectURI;
		
		Object v = o.get("redirect_uri");
		
		if (v == null || ! (v instanceof String))
			throw new ResolveException("Invalid \"redirect_uri\" parameter: Must be a string and not null");
		
		try {
			return new URL((String)v);
			
		} catch (MalformedURLException e) {
		
			throw new ResolveException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Sets the redirection URL. Corresponds to the {@code redirection_uri}
	 * parameter.
	 *
	 * @param redirectURI The redirection URI. Must not be {@code null}.
	 */
	public void setRedirectURI(final URL redirectURI) {
	
		if (redirectURI == null)
			throw new NullPointerException("The redirect URI must not be null");
			
		this.redirectURI = redirectURI;
	}
	
	
	/**
	 * Gets the nonce. Corresponds to the {@code nonce} parameter.
	 *
	 * @return The nonce.
	 */
	public Nonce getNonce() {
	
		return nonce;
	}
	
	
	/**
	 * Gets the resolved nonce.
	 *
	 * <p>The following precendence applies:
	 *
	 * <ol>
	 *     <li>The value from the OpenID request object (if any).
	 *     <li>The value from the main request.
	 * </ol>
	 *
	 * @return The nonce from the OpenID request object (if any), else the 
	 *         nonce from the main request.
	 *
	 * @throws ResolveException If the resolve operation failed.
	 */
	public Nonce getResolvedNonce()
		throws ResolveException {
	
		if (! this.hasRequestObject())
			return nonce;
		
		JSONObject o = getResolvedRequestObjectJSON();
		
		if (! o.containsKey("nonce"))
			return nonce;
		
		Object v = o.get("nonce");
		
		if (v == null || ! (v instanceof String))
			throw new ResolveException("Invalid \"nonce\" parameter: Must be a string and not null");
		
		return new Nonce((String)v);
	}
	
	
	/**
	 * Sets the nonce. Corresponds to the {@code nonce} parameter.
	 *
	 * @param nonce The nonce. Must not be {@code null}.
	 */
	public void setNonce(final Nonce nonce) {
	
		if (nonce == null)
			throw new NullPointerException("The nonce must not be null");
		
		this.nonce = nonce;
	}
	
	
	/**
	 * Gets the state. Corresponds to the recommended {@code state} 
	 * parameter.
	 *
	 * @return The state. {@code null} if not specified.
	 */
	public State getState() {
	
		return state;
	}
	
	
	/**
	 * Gets the resolved state.
	 *
	 * <p>The following precendence applies:
	 *
	 * <ol>
	 *     <li>The value from the OpenID request object (if any).
	 *     <li>The value from the main request.
	 * </ol>
	 *
	 * @return The state from the OpenID request object (if any), else the 
	 *         state from the main request.
	 *
	 * @throws ResolveException If the resolve operation failed.
	 */
	public State getResolvedState()
		throws ResolveException {
	
		if (! this.hasRequestObject())
			return state;
		
		JSONObject o = getResolvedRequestObjectJSON();
		
		if (! o.containsKey("state"))
			return state;
		
		Object v = o.get("state");
		
		if (v == null || ! (v instanceof String))
			throw new ResolveException("Invalid \"state\" parameter: Must be a string and not null");
		
		return new State((String)v);
	}
	
	
	/**
	 * Sets the state. Corresponds to the recommended {@code state} 
	 * parameter.
	 *
	 * @param state The state. {@code null} if not specified.
	 */
	public void setState(final State state) {
	
		this.state = state;
	}
	
	
	/**
	 * Gets the requested display type. Corresponds to the optional
	 * {@code display} parameter.
	 *
	 * @return The requested display type. {@code null} if not specified.
	 */
	public Display getDisplay() {
	
		return display;
	}
	
	
	/**
	 * Gets the resolved requested display type.
	 *
	 * <p>The following precendence applies:
	 *
	 * <ol>
	 *     <li>The value from the OpenID request object (if any).
	 *     <li>The value from the main request.
	 * </ol>
	 *
	 * @return The requested display type from the OpenID request object (if 
	 *         any), else the requested display type from the main request.
	 *
	 * @throws ResolveException If the resolve operation failed.
	 */
	public Display getResolvedDisplay()
		throws ResolveException {
		
		if (! this.hasRequestObject())
			return display;
		
		JSONObject o = getResolvedRequestObjectJSON();
		
		if (! o.containsKey("display"))
			return display;
		
		Object v = o.get("display");
		
		if (v == null || ! (v instanceof String))
			throw new ResolveException("Invalid \"display\" parameter: Must be a string and not null");
		
		try {
			return Display.parse((String)v);
			
		} catch (ParseException e) {
		
			throw new ResolveException("Invalid \"display\" parameter: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Sets the requested display type. Corresponds to the optional
	 * {@code display} parameter.
	 *
	 * @param display The requested display type. {@code null} if not 
	 *                specified.
	 */
	public void setDisplay(final Display display) {
	
		this.display = display;
	}
	
	
	/**
	 * Gets the requested prompt. Corresponds to the optional {@code prompt}
	 * parameter.
	 *
	 * @return The requested prompt. {@code null} if not specified.
	 */
	public Prompt getPrompt() {
	
		return prompt;
	}
	
	
	/**
	 * Gets the resolved requested prompt.
	 *
	 * <p>The following precendence applies:
	 *
	 * <ol>
	 *     <li>The value from the OpenID request object (if any).
	 *     <li>The value from the main request.
	 * </ol>
	 *
	 * @return The requested prompt from the OpenID request object (if any), 
	 *         else the requested prompt from the main request.
	 *
	 * @throws ResolveException If the resolve operation failed.
	 */
	public Prompt getResolvedPrompt()
		throws ResolveException {
	
		if (! this.hasRequestObject())
			return prompt;
		
		JSONObject o = getResolvedRequestObjectJSON();
		
		if (! o.containsKey("prompt"))
			return prompt;
		
		Object v = o.get("prompt");
		
		if (v == null || ! (v instanceof String))
			throw new ResolveException("Invalid \"prompt\" parameter: Must be a string and not null");
		
		try {
			return Prompt.parse((String)v);
			
		} catch (ParseException e) {
		
			throw new ResolveException("Invalid \"prompt\" parameter: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Sets the requested prompt. Corresponds to the optional {@code prompt}
	 * parameter.
	 *
	 * @param prompt The requested prompt. {@code null} if not specified.
	 */
	public void setPrompt(final Prompt prompt) {
	
		this.prompt = prompt;
	}
	
	
	/**
	 * Gets the JSON Web Token (JWT) encoded OpenID request object.
	 *
	 * @return The request object, {@code null} if not specified.
	 */
	public JWT getRequestObject() {
	
		return requestObject;
	}
	
	
	/**
	 * Sets the JSON Web Token (JWT) encoded OpenID request object.
	 *
	 * @param requestObject The request object, {@code null} if not 
	 *                      specified.
	 *
	 * @throws IllegalStateException If an OpenID request object is already
	 *                               specified by URI reference.
	 */
	public void setRequestObject(final JWT requestObject) {
	
		if (requestURI != null)
			throw new IllegalStateException("An OpenID request object is already specified by URI reference");
			
		this.requestObject = requestObject;
		
		// Clear cached resolved request object
		resolvedRequestObject = null;
	}
	
	
	/**
	 * Gets the URI that points to an OpenID request object.
	 *
	 * @return The OpenID request object URI, {@code null} if not specified.
	 */
	public URL getRequestObjectURI() {
	
		return requestURI;
	}
	
	
	/**
	 * Sets the URI that points to an OpenID request object.
	 *
	 * @param requestURI The OpenID request object URI, {@code null} if not
	 *                   specified.
	 *
	 * @throws IllegalStateException If an OpenID request object is already
	 *                               specified by a JWT.
	 */
	public void setRequestObjectURI(final URL requestURI) {
	
		if (requestObject != null)
			throw new IllegalStateException("An OpenID request object is already specified by a JWT");
	
		this.requestURI = requestURI;
		
		// Clear cached resolved request object
		resolvedRequestObject = null;
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
	
		if (requestObject != null || requestURI != null)
			return true;
		else
			return false;
	}
	
	
	/**
	 * Downloads a JWT-encoded OpenID request object at the specified URL.
	 *
	 * @param url The request object URL. Must not be {@code null}.
	 *
	 * @return The downloaded JWT-encoded OpenID request object.
	 *
	 * @throws IOException  If the HTTP connection to the specified URL 
	 *                      failed.
	 * @throws JWTException If the content at the specified URL couldn't be
	 *                      parsed to a valid JSON Web Token (JWT).
	 */
	protected static JWT downloadRequestObject(final URL url)
		throws IOException, JWTException {
		
		HttpURLConnection con = (HttpURLConnection)url.openConnection();
		
		StringBuilder sb = new StringBuilder();
		
		BufferedReader input = new BufferedReader(new InputStreamReader(con.getInputStream()));
		
		String line = null;
		
		while ((line = input.readLine()) != null) {
		
			sb.append(line);
			sb.append(System.getProperty("line.separator"));
		}
		
		input.close();
		
		// Save HTTP code + message
		final int statusCode = con.getResponseCode();
		final String statusMessage = con.getResponseMessage();
		
		return JWT.parse(sb.toString());
	}
	
	
	/**
	 * Resolves the OpenID request object (if any).
	 *
	 * @throws ResolveException For a request object URI that couldn't be
	 *                          resolved to a valid JWT.
	 */
	private void resolveRequestObject()
		throws ResolveException {
	
		// Do we have a request object?
		if (! this.hasRequestObject())
			return;
	
		if (requestObject != null) {
		
			resolvedRequestObject = requestObject;
		}
		else if (requestURI != null) {
		
			try {
				resolvedRequestObject = downloadRequestObject(requestURI);
				
			} catch (IOException e) {
			
				throw new ResolveException("Couldn't resolve request object: " + e.getMessage(), e);
				
			} catch (JWTException e) {
			
				throw new ResolveException("Couldn't resolve request object: " + e.getMessage(), e);
			}
		}
	}
	
	
	/**
	 * Gets the resolved OpenID request object.
	 *
	 * <p>The OpenID request object is resolved as follows:
	 *
	 * <ul>
	 *     <li>If no request object is specified this method returns 
	 *         {@code null}.
	 *     <li>If the request object is specified directly by a 
	 *         {@code request} parameter this method returns the same value 
	 *         as {@link #getRequestObject}.
	 *     <li>If the request object is specified by a {@code request_uri} 
	 *         parameter this method returns the referenced JWT.
	 * </ul>
	 *
	 * @return The resolved request object, {@code null} if not specified.
	 *
	 * @throws ResolveException For a request object URI that couldn't be
	 *                          resolved to a valid JWT.
	 */
	public JWT getResolvedRequestObject()
		throws ResolveException {
	
		if (! this.hasRequestObject())
			return null;
		
		// Cached object?
		if (resolvedRequestObject == null)
			resolveRequestObject();
		
		return resolvedRequestObject;
	}
	
	
	/**
	 * Gets the JSON object of the resolved OpenID request object.
	 *
	 * @return The resolved OpenID request object JSON.
	 *
	 * @throws ResolveException If resolution failed, the JWT is not in the
	 *                          required state (verified for signed JWTs or
	 *                          decrypted for encrypted JWTs) or the request
	 *                          object JSON is invalid.
	 */
	private JSONObject getResolvedRequestObjectJSON()
		throws ResolveException {
		
		if (requestObjectJSON == null) {
		
			JWT jwt = getResolvedRequestObject();
			
			if (jwt instanceof SignedJWT && 
			    ((SignedJWT)jwt).getState() != SignedJWT.State.VERIFIED)
				throw new ResolveException("The request object JWT is signed and must be verified first");
			
			else if (jwt instanceof EncryptedJWT &&
			         ((EncryptedJWT)jwt).getState() != EncryptedJWT.State.DECRYPTED)
				throw new ResolveException("The request object JWT is encrypted and must be decrypted first");
			
			requestObjectJSON = jwt.getClaimsSet().toJSONObject();
			
			if (requestObjectJSON == null)
				throw new ResolveException("Invalid request object (JWT) JSON");
		}
		
		// Validate existence of mandatory response_type and scope
		if (! requestObjectJSON.containsKey("response_type"))
			throw new ResolveException("Missing \"response_type\" parameter in the request object (JWT)");
		
		if (! requestObjectJSON.containsKey("scope"))
			throw new ResolveException("Missing \"scope\" parameter in the request object (JWT)");
		
		return requestObjectJSON;
	}
	
	
	/**
	 * Gets the resolved ID Token claims request.
	 *
	 * @return The resolved ID Token claims request.
	 *
	 * @throws ResolveException If the ID Token claims request cannot be
	 *                          resolved.
	 */
	public ResolvedIDTokenClaimsRequest getResolvedIDTokenClaimsRequest()
		throws ResolveException {
	
		// Return default ID token claims request?
		if (! this.hasRequestObject())
			return new ResolvedIDTokenClaimsRequest(null);
	
		JSONObject reqObj = getResolvedRequestObjectJSON();
		
		if (! reqObj.containsKey("id_token"))
			return new ResolvedIDTokenClaimsRequest(null);
		
		if (! (reqObj.get("id_token") instanceof JSONObject))
			throw new ResolveException("Unexpected \"id_token\" type, must be JSON object");
		
		JSONObject idTokenObj = (JSONObject)reqObj.get("id_token");
		
		return new ResolvedIDTokenClaimsRequest(idTokenObj);
	}
	
	
	/**
	 * Gets the resolved User Info claims request.
	 *
	 * @return The resolved User Info claims request.
	 *
	 * @throws ResolveException If the User Info claims request cannot be
	 *                          resolved.
	 */
	public ResolvedUserInfoClaimsRequest getResolvedUserInfoClaimsRequest()
		throws ResolveException {
	
		// Return default UserInfo claims request?
		if (! this.hasRequestObject())
			return new ResolvedUserInfoClaimsRequest(getResolvedScope(), null);
		
		JSONObject reqObj = getResolvedRequestObjectJSON();
	
		// Path: { user_info : {claims : {...}}}
		
		if (! reqObj.containsKey("userinfo"))
			return new ResolvedUserInfoClaimsRequest(getResolvedScope(), null);
		
		if (! (reqObj.get("userinfo") instanceof JSONObject))
			throw new ResolveException("Unexpected \"userinfo\" type, must be JSON object");
		
		JSONObject userInfoObj = (JSONObject)reqObj.get("userinfo");
		
		return new ResolvedUserInfoClaimsRequest(getResolvedScope(), userInfoObj);
	}
	
	
	/**
	 * @inheritDoc
	 */
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
	
		return null;
	}
	
	
	/**
	 * Parses an authorisation request from the specified URL query string.
	 *
	 * <p>Example URL query string:
	 *
	 * <pre>
	 * ?response_type=token%20id_token
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
		
		if (v == null || v.trim().isEmpty())
			throw new ParseException("Missing \"response_type\" parameter");
		
		ResponseTypeSet rts = null;
		
		try {
			rts = ResponseTypeSet.parse(v);
		
		} catch (ParseException e) {
			
			throw new ParseException("Invalid \"response_type\" parameter: " + e.getMessage(), e);
		}
			
		v = params.get("scope");
		
		if (v == null || v.trim().isEmpty())
			throw new ParseException("Missing \"scope\" parameter");
		
		Scope scope = null;
		
		try {
			scope = Scope.parseStrict(v);
			
		} catch (ParseException e) {
		
			throw new ParseException("Invalid \"scope\" parameter: " + e.getMessage(), e);
		}
		
		
		v = params.get("client_id");
		
		if (v == null || v.trim().isEmpty())
			throw new ParseException("Missing \"client_id\" parameter");
		
		ClientID clientID = new ClientID();
		clientID.setClaimValue(v);
		
		
		v = params.get("redirect_uri");
		
		if (v == null || v.trim().isEmpty())
			throw new ParseException("Missing \"redirect_uri\" parameter");
			
		URL redirectURI = null;
		
		try {
			redirectURI = new URL(v);
			
		} catch (MalformedURLException e) {
		
			throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), e);
		}
		
		v = params.get("nonce");
		
		if (v == null || v.trim().isEmpty())
			throw new ParseException("Missing \"nonce\" parameter");
		
		Nonce nonce = new Nonce(v);
		
		
		AuthorizationRequest request = new AuthorizationRequest(rts, scope, clientID, redirectURI, nonce);
		
		
		// Optional params
		
		v = params.get("state");
		
		if (v != null && ! v.trim().isEmpty())
			request.setState(new State(v));
		
		
		v = params.get("display");
		
		if (v != null && ! v.trim().isEmpty()) {
		
			try {
				request.setDisplay(Display.parse(v));
				
			} catch (ParseException e) {
				
				throw new ParseException("Invalid \"display\" parameter: " + e.getMessage(), e);
			}
		}
		
		v = params.get("prompt");
		
		if (v != null && ! v.trim().isEmpty()) {
		
			try {
				request.setPrompt(Prompt.parse(v));
				
			} catch (ParseException e) {
			
				throw new ParseException("Invalid \"prompt\" parameter: " + e.getMessage(), e);
			}
		}
		
		
		v = params.get("request");
		
		if (v != null && ! v.trim().isEmpty()) {
		
			try {
				request.setRequestObject(JWT.parse(v));
				
			} catch (JWTException e) {
			
				throw new ParseException("Invalid \"request\" parameter: " + e.getMessage(), e);
			}
		}
		
		v = params.get("request_uri");
		
		if (v != null && ! v.trim().isEmpty()) {
	
			// request_object and request_uri must not be defined at the same time
			if (request.hasRequestObject())
				throw new ParseException("Invalid request: Found mutually exclusive \"request_object\" and \"request_uri\"");
	
			try {
				request.setRequestObjectURI(new URL(v));
		
			} catch (MalformedURLException e) {
			
				throw new ParseException("Invalid \"redirect_uri\" parameter", e);
			}
		}
	
		return request;
	}
	
	
	/**
	 * Parses an authorisation request from the specified HTTP request.
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
