package com.nimbusds.openid.connect.messages;


import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.claims.ClientID;

import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * Client registration response.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-12)
 */
public class ClientRegistrationResponse implements Response {


	/**
	 * The unique client identifier (required).
	 */
	private ClientID clientID;
	
	
	/**
	 * The client secret (required).
	 */
	private String clientSecret;
	
	
	/**
	 * The number of seconds from 1970-01-01T0:0:0Z as measured in UTC that 
	 * the {@link #clientID} and {@link #clientSecret} will expire or 0 if 
	 * they do not expire (required).
	 */
	private long expiresAtTime;
	
	
	
	public ClientRegistrationResponse(final ClientID clientID, 
	                                  final String clientSecret,
					  final long expiresAtTime) {
					  
	
		if (clientID == null)
			throw new NullPointerException("The client identifier must not be null");
			
		this.clientID = clientID;
		
		
		if (clientSecret == null)
			throw new NullPointerException("The client secret must not be null");
		
		this.clientSecret = clientSecret;
		
		if (expiresAtTime < 0)
			throw new IllegalArgumentException("The expires at time value must be zero or positive");
		
		this.expiresAtTime = expiresAtTime;
	}
	
	
	
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("client_id", clientID.toString());
		o.put("client_secret", clientSecret);
		o.put("expires_at", expiresAtTime);
		
		return o;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public HTTPResponse toHTTPResponse() {
	
		return null;
	}
	
	
	public String toString() {
	
		return toJSONObject().toString();
	}
}
