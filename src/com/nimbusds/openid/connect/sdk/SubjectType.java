package com.nimbusds.openid.connect.sdk;


/**
 * Enumeration of the subject identifier types.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-22)
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
}