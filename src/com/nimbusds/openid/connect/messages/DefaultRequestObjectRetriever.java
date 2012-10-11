package com.nimbusds.openid.connect.messages;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import java.net.HttpURLConnection;
import java.net.URL;

import com.nimbusds.jose.JOSEObject;

import com.nimbusds.openid.connect.ParseException;


/**
 * Simple retriever of OpenID Connect request objects referenced by URL.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-11)
 */
public class DefaultRequestObjectRetriever implements RequestObjectRetriever {


	/**
	 * The system line separator.
	 */
	final String lineSeparator;
	
	
	/**
	 * Creates a new retriever of OpenID Connect request objects.
	 */
	public DefaultRequestObjectRetriever() {
	
		lineSeparator = System.getProperty("line.separator");
	}
	
	
	@Override	
	public JOSEObject downloadRequestObject(final URL url)
		throws IOException, ParseException {
		
		HttpURLConnection con = (HttpURLConnection)url.openConnection();
		
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
		
			throw new ParseException("Couldn't parse JOSE request object: " + e.getMessage(), e);
		}
	}
}
