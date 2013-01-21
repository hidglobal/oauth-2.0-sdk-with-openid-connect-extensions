package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Enumeration of the display types for authentication and consent UIs. This
 * class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
 */
public enum Display {


	/**
	 * Full user-agent page view (default).
	 */
	PAGE,
	
	
	/**
	 * Popup user-agent window.
	 */
	POPUP,
	
	
	/**
	 * Device that leverages a touch interface. The authorisation server may
	 * attempt to detect the touch device and further customise the 
	 * interface.
	 */
	TOUCH,
	
	
	/**
	 * Feature phone.
	 */
	WAP;


	/**
	 * Gets the default display type ({@link #PAGE}).
	 *
	 * @return The default display type.
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
	
		if (StringUtils.isUndefined(s))
			return getDefault();
		
		if (s.equals("page"))
			return PAGE;
			
		else if (s.equals("popup"))
			return POPUP;
			
		else if (s.equals("touch"))
			return TOUCH;
			
		else if (s.equals("wap"))
			return WAP;
			
		else
			throw new ParseException("Unknown display type: " + s);
	}
}