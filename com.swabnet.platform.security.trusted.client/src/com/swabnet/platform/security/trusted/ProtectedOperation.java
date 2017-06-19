package com.swabnet.platform.security.trusted;

import java.security.PrivilegedAction;

/**
 * 
 * A computation to be performed with privileges enabled. 
 * 
 * @author vladimir.novick
 *
 */
public abstract class ProtectedOperation implements PrivilegedAction {

	/**
	 * 
	 * Associate the current login security subject and 
     *  execute the Privileged action @see SecurityClient 
	 * 
	 * @return Object
	 */
	public abstract Object run();

}
