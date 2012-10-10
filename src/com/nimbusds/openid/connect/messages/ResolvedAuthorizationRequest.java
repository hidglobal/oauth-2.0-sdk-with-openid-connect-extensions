package com.nimbusds.openid.connect.messages;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.claims.ClientID;

import com.nimbusds.openid.connect.http.HTTPRequest;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Resolved authorisation request.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-09)
 */
public class ResolvedAuthorizationRequest {


	/**
	 * The response type set (required).
	 */
	private final ResponseTypeSet rts = null;
	
	
	/**
	 * The client identifier (required).
	 */
	private final ClientID clientID = null;
	
	
	/**
	 * The redirection URI where the response will be sent (required). 
	 */
	private final URL redirectURI = null;
	
	
	/**
	 * The nonce (required for implicit flow, optional for code flow).
	 */
	private final Nonce nonce = null;
	
	
	/**
	 * The opaque value to maintain state between the request and the 
	 * callback (recommended).
	 */
	private final State state = null;
	
	
	/**
	 * The requested display type (optional).
	 */
	private final Display display = null;
	
	
	/**
	 * The requested prompt (optional).
	 */
	private final Prompt prompt = null;
	
	
	/**
	 * An ID Token passed as a hint about the user's current or past 
	 * authenticated session with the client (optional). Should be present 
	 * if {@code prompt=none} is sent.
	 */
	private final JWT idTokenHint = null;
	
	
	
}
