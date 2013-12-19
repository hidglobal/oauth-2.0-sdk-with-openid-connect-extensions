package com.nimbusds.openid.connect.sdk;


import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Enumeration of the display types for authentication and consent UIs.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.2.1.
 * </ul>
 */
public enum Display {


	/**
	 * Full user-agent page view (default).
	 */
	PAGE,
	
	
	/**
	 * Popup user-agent window. The popup User Agent window should be of an
	 * appropriate size for a login-focused dialog and should not obscure
	 * the entire window that it is popping up over.
	 */
	POPUP,
	
	
	/**
	 * Device that leverages a touch interface. The authorisation server 
	 * may attempt to detect the touch device and further customise the 
	 * interface.
	 */
	TOUCH,
	
	
	/**
	 * Feature phone.
	 */
	WAP;


	/**
	 * Gets the default display type.
	 *
	 * @return The default display type ({@link #PAGE}).
	 */
	public static Display getDefault() {
	
		return PAGE;
	}
	
	
	/**
	 * Returns the string identifier of this display type.
	 *
	 * @return The string identifier.
	 */
	@Override
	public String toString() {
	
		return super.toString().toLowerCase();
	}
	
	
	/**
	 * Parses a display type.
	 *
	 * @param s The string to parse. If the string is {@code null} or empty
	 *          the {@link #getDefault} display type will be returned.
	 *
	 * @return The display type.
	 *
	 * @throws ParseException If the parsed string doesn't match a display 
	 *                        type.
	 */
	public static Display parse(final String s)
		throws ParseException {
	
		if (StringUtils.isBlank(s))
			return getDefault();
		
		if (s.equals("page"))
			return PAGE;
			
		if (s.equals("popup"))
			return POPUP;
			
		if (s.equals("touch"))
			return TOUCH;
			
		if (s.equals("wap"))
			return WAP;
			
		throw new ParseException("Unknown display type: " + s);
	}
}
