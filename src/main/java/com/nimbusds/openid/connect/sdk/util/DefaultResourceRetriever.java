package com.nimbusds.openid.connect.sdk.util;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.mail.internet.ContentType;
import javax.mail.internet.ParseException;

import net.jcip.annotations.ThreadSafe;


/**
 * The default retriever of resources specified by URL. Provides setting of
 * HTTP connect and read timeouts. Caching header directives are not honoured. 
 * This class is thread-safe.
 */
@ThreadSafe
public class DefaultResourceRetriever implements ResourceRetriever {


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
	 * Creates a new resource retriever. The HTTP connect and read timeouts
	 * are set to zero (infinite).
	 */
	public DefaultResourceRetriever() {
	
		this(0, 0);	
	}
	
	
	/**
	 * Creates a new resource retriever.
	 *
	 * @param connectTimeout The HTTP connects timeout, in milliseconds, 
	 *                       zero for infinite. Must not be negative.
	 * @param readTimeout    The HTTP read timeout, in milliseconds, zero 
	 *                       for infinite. Must not be negative.
	 */
	public DefaultResourceRetriever(final int connectTimeout, final int readTimeout) {
	
		setConnectTimeout(connectTimeout);
		setReadTimeout(readTimeout);
		
		lineSeparator = System.getProperty("line.separator");
	}
	
	
	/**
	 * Gets the HTTP connect timeout.
	 *
	 * @return The HTTP connect timeout, in milliseconds, zero for 
	 *         infinite.
	 */
	public int getConnectTimeout() {
	
		return connectTimeout;
	}
	
	
	/**
	 * Sets the HTTP connect timeout.
	 *
	 * @param connectTimeout The HTTP connect timeout, in milliseconds, 
	 *                       zero for infinite. Must not be negative.
	 */
	public void setConnectTimeout(final int connectTimeout) {
	
		if (connectTimeout < 0)
			throw new IllegalArgumentException("The connect timeout must not be negative");
		
		this.connectTimeout = connectTimeout;
	}
	
	
	/**
	 * Gets the HTTP read timeout.
	 *
	 * @return The HTTP read timeout, in milliseconds, zero for infinite.
	 */
	public int getReadTimeout() {
	
		return readTimeout;
	}
	
	
	/**
	 * Sets the HTTP read timeout.
	 *
	 * @param readTimeout The HTTP read timeout, in milliseconds, zero for
	 *                    infinite. Must not be negative.
	 */
	public void setReadTimeout(final int readTimeout) {
	
		if (readTimeout < 0)
			throw new IllegalArgumentException("The read timeout must not be negative");
		
		this.readTimeout = readTimeout;
	}
	
	
	@Override	
	public Resource retrieveResource(final URL url)
		throws IOException {
		
		HttpURLConnection con;

		try {
			con = (HttpURLConnection)url.openConnection();

		} catch (ClassCastException e) {

			throw new IOException("Couldn't open HTTP(S) connection: " + e.getMessage(), e);
		}

		con.setConnectTimeout(connectTimeout);
		con.setReadTimeout(readTimeout);
		
		StringBuilder sb = new StringBuilder();
		
		BufferedReader input = new BufferedReader(new InputStreamReader(con.getInputStream()));
		
		String line;
		
		while ((line = input.readLine()) != null) {
		
			sb.append(line);
			sb.append(lineSeparator);
		}
		
		input.close();
		
		// Check HTTP code + message
		final int statusCode = con.getResponseCode();
		final String statusMessage = con.getResponseMessage();

		if (statusCode != HttpURLConnection.HTTP_OK) {

			throw new IOException("HTTP " + statusCode + ": " + statusMessage);
		}

		// Parse the Content-Type header
		ContentType contentType = null;

		if (con.getContentType() != null) {

			try {
				contentType = new ContentType(con.getContentType());

			} catch (ParseException e) {

				throw new IOException("Couldn't parse Content-Type header: " + e.getMessage(), e);
			}
		}
		
		return new Resource(sb.toString(), contentType);
	}
}
