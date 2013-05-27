package com.nimbusds.openid.connect.sdk.op;


import java.net.URL;
import java.util.List;

import net.jcip.annotations.Immutable;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.jwt.JWT;

import com.nimbusds.oauth2.sdk.ResponseTypeSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCAuthorizationRequest;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;


/**
 * Resolved OpenID Connect authorisation request. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class ResolvedOIDCAuthorizationRequest extends OIDCAuthorizationRequest {


	/**
	 * Creates a new resolved OpenID Connect authorisation request. Any
	 * pre-existing parameters specified by means of the OpenID Connect
	 * request object have been merged into it.
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
	 * @param claims        The individual claims to be returned. 
	 *                      Corresponds to the optional {@code claims} 
	 *                      parameter. {@code null} if not specified.
	 */
	public ResolvedOIDCAuthorizationRequest(final ResponseTypeSet rts,
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
				    
				    
		super(rts, scope, clientID, redirectURI, state, nonce, display, prompt,
		      maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues,
		      claims);
	}
}