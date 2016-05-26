package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Enumeration of the subject identifier types.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.
 * </ul>
 */
public enum SubjectType {


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


        /**
         * Parses a subject identifier type.
         *
         * @param s The string to parse.
         *
         * @return The subject identifier type.
         *
         * @throws ParseException If the parsed string is {@code null} or
         *                        doesn't match a subject identifier type.
         */
        public static SubjectType parse(final String s)
                throws ParseException {

                if (s == null || s.trim().isEmpty())
                        throw new ParseException("Null or empty subject type string");

		if ("pairwise".equals(s)) {

			return PAIRWISE;

		} else if ("public".equals(s)) {

			return PUBLIC;

		} else {

			throw new ParseException("Unknown subject type: " + s);
		}
        }
}