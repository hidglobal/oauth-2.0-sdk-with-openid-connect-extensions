package com.nimbusds.openid.connect.sdk.op;


import java.net.URL;

import net.jcip.annotations.Immutable;

import com.nimbusds.jwt.JWT;

import com.nimbusds.oauth2.sdk.ResponseTypeSet;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * Resolved OpenID Connect authorisation request. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class ResolvedOIDCAuthorizationRequest {


	/**
	 * The response type set (required).
	 */
	private final ResponseTypeSet rts;
	
	
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
	 * The requested display type (optional, with default value).
	 */
	private final Display display;
	
	
	/**
	 * The requested prompt (optional).
	 */
	private final Prompt prompt;
	
	
	/**
	 * An ID Token passed as a hint about the user's current or past 
	 * authenticated session with the client (optional). Should be present 
	 * if {@code prompt=none} is sent.
	 */
	private final JWT idTokenHint;


	/**
	 * The login hint (optional).
	 */
	private final String loginHint;

	
	
	/**
	 * The resolved ID Token claims request (optional).
	 */
	private final IDTokenClaimsRequest idTokenClaimsRequest;
	
	
	/**
	 * The resolved UserInfo claims request (optional).
	 */
	private final UserInfoClaimsRequest userInfoClaimsRequest;
	
	
	
	/**
	 * Creates a new resolved OpenID Connect authorisation request.
	 *
	 * @param rts            The response type set. Corresponds to the 
	 *                       {@code response_type} parameter. Must not be
	 *                       {@code null}.
	 * @param clientID       The client identifier. Corresponds to the
	 *                       {@code client_id} parameter. Must not be 
	 *                       {@code null}.
	 * @param redirectURI    The redirection URI. Corresponds to the
	 *                       {@code redirect_uri} parameter. Must not be 
	 *                       {@code null}.
	 * @param nonce          The nonce. Corresponds to the {@code nonce} 
	 *                       parameter. May be {@code null} for code flow.
	 * @param state          The state. Corresponds to the recommended 
	 *                       {@code state} parameter. {@code null} if not 
	 *                       specified.
	 * @param display        The requested display type. Corresponds to the 
	 *                       optional {@code display} parameter which has a
	 *                       default value. Must not be {@code null}.
	 * @param prompt         The requested prompt. Corresponds to the 
	 *                       optional {@code prompt} parameter. 
	 *                       {@code null} if not specified.
	 * @param idTokenHint    The ID Token hint. Corresponds to the optional 
	 *                       {@code id_token_hint} parameter. {@code null}
	 *                       if not specified.
	 * @param loginHint      The login hint. Corresponds to the optional
	 *                       {@code login_hint} parameter. {@code null} if
	 *                       not specified.
	 * @param idTokenClaims  The resolved ID Token claims request. If
	 *                       {@code null} an ID Token is not requested.
	 * @param userInfoClaims The resolved UserInfo claims request. If
	 *                       {@code null} UserInfo is not requested.
	 */
	public ResolvedOIDCAuthorizationRequest(final ResponseTypeSet rts,
	                                        final ClientID clientID,
					        final URL redirectURI,
					        final Nonce nonce,
					        final State state,
					        final Display display,
					        final Prompt prompt,
					        final JWT idTokenHint,
					        final String loginHint,
					        final IDTokenClaimsRequest idTokenClaims,
					        final UserInfoClaimsRequest userInfoClaims) {
					    
		
		if (rts == null)
			throw new IllegalArgumentException("The response type set must not be null");
		
		this.rts = rts;
		
		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");
			
		this.clientID = clientID;
		
		if (redirectURI == null)
			throw new IllegalArgumentException("The redirect URI must not be null");
			
		this.redirectURI = redirectURI;
		
		this.nonce = nonce;
		
		this.state = state;
		
		if (display == null)
			throw new IllegalArgumentException("The display must not be null");

		this.display = display;
		
		this.prompt = prompt;
		
		this.idTokenHint = idTokenHint;

		this.loginHint = loginHint;
		
		this.idTokenClaimsRequest = idTokenClaims;
		
		this.userInfoClaimsRequest = userInfoClaims;
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
	 * {@code display} parameter which has a default value.
	 *
	 * @return The requested display type.
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
	
	
	/**
	 * Gets the resolved ID Token claims request.
	 *
	 * @return The ID Token claims request, {@code null} if an ID Token is
	 *         not requested.
	 */
	public IDTokenClaimsRequest getIDTokenClaimsRequest() {
	
		return idTokenClaimsRequest;
	}
	
	
	/**
	 * Gets the resolved UserInfo claims request.
	 *
	 * @return The UserInfo claims request, {@code null} if UserInfo is not
	 *         requested.
	 */
	public UserInfoClaimsRequest getUserInfoClaimsRequest() {
	
		return userInfoClaimsRequest;
	}
}
