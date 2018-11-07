package com.solace.srajgopalan.ldapInterceptor;

import com.unboundid.ldap.sdk.Entry;

/**
 * This class describes a simple Entry record in our
 * file based authentication system.
 * An Entry consists of three parts:
 *   - CN (username)
 *   - Password
 *   - Group membership attribute
 */

public class MockAuthSystemEntry {
	private String dn;
	private String userPassword;
	private Entry entry;

	public String getDn() {
		return dn;
	}
	public void setDn(String dn) {
		this.dn = dn;
	}
	public String getUserPassword() {
		return userPassword;
	}
	public void setUserPassword(String userPassword) {
		this.userPassword = userPassword;
	}
	public Entry getEntry() {
		return entry;
	}
	public void setEntry(Entry entry) {
		this.entry = entry;
	}

    @Override
    public String toString() {
        return "MockAuthSystemEntry{" +
                "dn='" + dn + '\'' +
                ", userPassword='" + userPassword + '\'' +
                ", entry=" + entry +
                '}';
    }
}
