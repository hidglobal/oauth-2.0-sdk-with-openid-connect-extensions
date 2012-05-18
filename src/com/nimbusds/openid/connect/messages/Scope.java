package com.nimbusds.openid.connect.messages;


import java.util.HashSet;
import java.util.Iterator;

import com.nimbusds.openid.connect.ParseException;


/**
 * UserInfo {@link AuthorizationRequest authorisation request} scope.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-22)
 */
public class Scope extends HashSet<ScopeMember> {

	
	/**
	 * Creates a new empty authorisation request scope.
	 */
	public Scope() {
	
		// Nothing to do
	}
	
	
	/**
	 * Checks if the scope is valid according to the OpenID Connect 
	 * specification. This is done by examining if the scope contains an
	 * {@link StdScopeMember#OPENID} instance.
	 *
	 * @return {@code true} if this scope if valid, else {@code false}.
	 */
	public boolean isValid() {
	
		if (contains(StdScopeMember.OPENID))
			return true;
		else
			return false;
	}
	
	
	/**
	 * Returns the canonical string representation of this scope. The scope
	 * values are delimited by space.
	 *
	 * @return The string representation of this scope.
	 */
	public String toString() {
	
		StringBuilder sb = new StringBuilder();
	
		Iterator<ScopeMember> it = super.iterator();
		
		while (it.hasNext()) {
		
			sb.append(it.next().toString());
			
			if (it.hasNext())
				sb.append(" ");
		}
	
		return sb.toString();
	}
	
	
	/**
	 * Parses the specified scope string containing {@link StdScopeMember 
	 * standard scope members}.
	 *
	 * <p>See {@link ScopeParser}.
	 *
	 * @param s A string containing one or more standard scope members 
	 *          delimited by space.
	 *
	 * @return The parsed scope.
	 *
	 * @throws ParseException If an unexpected scope member is encountered
	 *                        or a {@link StdScopeMember#OPENID} is missing.
	 */
	public static Scope parseStrict(final String s)
		throws ParseException {
	
		return ScopeParser.STD_SCOPE_PARSER.parseStrict(s);
	}
}
