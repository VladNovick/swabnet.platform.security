/**
 * 
 */
package com.swabnet.platform.security.trusted;

import java.lang.reflect.Method;
import java.util.HashMap;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

/**
 * @author vladimir.novick
 * 
 */
public class LoginConfiguration extends Configuration {

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.security.auth.login.Configuration#getAppConfigurationEntry(java.lang.String)
	 */
	@Override
	public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
		AppConfigurationEntry[] entry = null;

		try {
			Class[] parameterTypes = {};

			Method m = getClass().getDeclaredMethod(name, parameterTypes);
			Object[] args = {};
			entry = (AppConfigurationEntry[]) m.invoke(this, args);
		} catch (Exception e) {

		}

		return entry;

	}

	AppConfigurationEntry[] other()

	{

		AppConfigurationEntry ace = new AppConfigurationEntry(
				WindowsLoginModule.class.getName(),
				AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
				new HashMap());
		AppConfigurationEntry[] entry = { ace };
		return entry;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.security.auth.login.Configuration#refresh()
	 */
	@Override
	public void refresh() {
		// TODO Auto-generated method stub

	}

}
