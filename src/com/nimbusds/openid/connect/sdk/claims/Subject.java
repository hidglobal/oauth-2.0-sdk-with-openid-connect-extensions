package com.nimbusds.openid.connect.sdk.claims;


/**
 * Subject identifier ({@code sub}). This is a locally unique and never 
 * reassigned identifier within the issuer for the end-user, intended to be 
 * consumed by the client.
 *
 * <p>The subject identifier cannot exceed {@link #MAX_LENGTH 255 ASCII 
 * characters} in length.
 *
 * <p>Example values:
 *
 * <pre>
 * 24400320
 * AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.1 and 2.4.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-11)
 */
public class Subject extends StringClaim {


	/**
	 * The maximum subject identifier length.
	 */
	public static final int MAX_LENGTH = 255;
	
	
	/**
	 * Enumeration of the subject identifier types.
	 */
	public static enum Type {
	
	
		/**
		 * Pairwise.
		 */
		PAIRWISE,
		
		
		/**
		 * Public.
		 */
		PUBLIC;
		
		
		/**
		 * Returns the string representation of this subject identifier 
		 * type.
		 *
		 * @return The string representation of this subject identifier
		 *         type.
		 */
		public String toString() {

			return super.toString().toLowerCase();
		}
	}
	
	
	/**
	 * Checks if the specified string represents a legal subject
	 * identifier.
	 *
	 * @return value The string to check.
	 *
	 * @return {@code true} if the string is not {@code null}, not empty
	 *         and is less than 256 characters length; else {@code false}.
	 */
	public static boolean isLegal(final String value) {
	
		if (value == null)
			return false;
		
		if (value.trim().isEmpty())
			return false;
			
		if (value.length() > MAX_LENGTH)	
			return false;
			
		return true; // OK
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @return "sub".
	 */
	@Override
	public String getClaimName() {
	
		return "sub";
	}
	
	
	/**
	 * Checks if the claim value represents a legal subject identifier.
	 *
	 * @return {@code true} if the value is less than 256 characters 
	 *         length, else {@code false}.
	 */
	public boolean isLegal() {
	
		return Subject.isLegal(this.getClaimValue());
	}
}
