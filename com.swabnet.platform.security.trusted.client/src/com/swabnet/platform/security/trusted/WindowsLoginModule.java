/**
 * 
 */
package com.swabnet.platform.security.trusted;

import javax.security.auth.login.LoginException;

import com.sun.security.auth.module.NTLoginModule;

/**
 * @author vladimir.novick
 *
 */
public class WindowsLoginModule extends NTLoginModule {

	/* (non-Javadoc)
	 * @see com.sun.security.auth.module.NTLoginModule#abort()
	 */
	@Override
	public boolean abort() throws LoginException {
		return super.abort();
	}

	/* (non-Javadoc)
	 * @see com.sun.security.auth.module.NTLoginModule#commit()
	 */
	@Override
	public boolean commit() throws LoginException {
		return super.commit();
	}

	/* (non-Javadoc)
	 * @see com.sun.security.auth.module.NTLoginModule#login()
	 */
	@Override
	public boolean login() throws LoginException {
		return super.login();
	}

	/* (non-Javadoc)
	 * @see com.sun.security.auth.module.NTLoginModule#logout()
	 */
	@Override
	public boolean logout() throws LoginException {
		return super.logout();
	}

	/**
	 * 
	 */
	public WindowsLoginModule() {
	}

}
