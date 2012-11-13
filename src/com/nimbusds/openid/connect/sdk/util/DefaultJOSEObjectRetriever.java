package com.nimbusds.openid.connect.sdk.util;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import java.net.HttpURLConnection;
import java.net.URL;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEObject;

import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * The default retriever of JOSE objects referenced by URL. Caching header 
 * directives are not honoured. This class is thread-safe.
 *
 * <p>Depending on network condition, retrieval of remote OpenID Connect request
 * objects may slow authorisation request processing significantly to affect 
 * smooth user experience. It is therefore recommended to set HTTP connect and
 * read timeouts.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-13)
 */
@ThreadSafe
public class DefaultJOSEObjectRetriever implements JOSEObjectRetriever {


	/**
	 * The system line separator.
	 */
	private final String lineSeparator;
	
	
	/**
	 * The HTTP connect timeout, in milliseconds.
	 */
	private int connectTimeout;
	
	
	/**
	 * The HTTP read timeout, in milliseconds.
	 */
	private int readTimeout;
	
	
	/**
	 * Creates a new retriever of JOSE objects. The HTTP connect and read 
	 * timeouts are set to zero (none).
	 */
	public DefaultJOSEObjectRetriever() {
	
		this(0, 0);	
	}
	
	
	/**
	 * Creates a new retriever of JOSE objects.
	 *
	 * @param connectTimeout The HTTP connects timeout, in milliseconds, 
	 *                       zero for none. Must not be negative.
	 * @param readTimeout    The HTTP read timeout, in milliseconds, zero 
	 *                       for none. Must not be negative.
	 */
	public DefaultJOSEObjectRetriever(final int connectTimeout, final int readTimeout) {
	
		setConnectTimeout(connectTimeout);
		setReadTimeout(readTimeout);
		
		lineSeparator = System.getProperty("line.separator");
	}
	
	
	/**
	 * Gets the HTTP connect timeout.
	 *
	 * @return The HTTP connect timeout, in milliseconds, zero for none.
	 */
	public int getConnectTimeout() {
	
		return connectTimeout;
	}
	
	
	/**
	 * Sets the HTTP connect timeout.
	 *
	 * @param connectTimeout The HTTP connect timeout, in milliseconds, zero
	 *                       for none. Must not be negative.
	 */
	public void setConnectTimeout(final int connectTimeout) {
	
		if (connectTimeout < 0)
			throw new IllegalArgumentException("The connect timeout must not be negative");
		
		this.connectTimeout = connectTimeout;
	}
	
	
	/**
	 * Gets the HTTP read timeout.
	 *
	 * @return The HTTP read timeout, in milliseconds, zero for none.
	 */
	public int getReadTimeout() {
	
		return readTimeout;
	}
	
	
	/**
	 * Sets the HTTP read timeout.
	 *
	 * @param readTimeout The HTTP read timeout, in milliseconds, zero for
	 *                    none. Must not be negative.
	 */
	public void setReadTimeout(final int readTimeout) {
	
		if (readTimeout < 0)
			throw new IllegalArgumentException("The read timeout must not be negative");
		
		this.readTimeout = readTimeout;
	}
	
	
	@Override	
	public JOSEObject downloadJOSEObject(final URL url)
		throws IOException, ParseException {
		
		HttpURLConnection con = (HttpURLConnection)url.openConnection();
		con.setConnectTimeout(connectTimeout);
		con.setReadTimeout(readTimeout);
		
		StringBuilder sb = new StringBuilder();
		
		BufferedReader input = new BufferedReader(new InputStreamReader(con.getInputStream()));
		
		String line = null;
		
		while ((line = input.readLine()) != null) {
		
			sb.append(line);
			sb.append(lineSeparator);
		}
		
		input.close();
		
		// Save HTTP code + message
		final int statusCode = con.getResponseCode();
		final String statusMessage = con.getResponseMessage();
		
		try {
			return JOSEObject.parse(sb.toString());
			
		} catch (java.text.ParseException e) {
		
			throw new ParseException("Couldn't parse JOSE object: " + e.getMessage(), e);
		}
	}
}
