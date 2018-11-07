package com.solace.srajgopalan.ldapInterceptor;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldif.LDIFException;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * This class stores a list of entries
 * defined in the file based authentication system
 *
 * It also exposes methods to allow a caller to
 * search the authentication records for a user
 * and retrieve its attributes, as well as
 * validate the password for a user in the
 * authentication system
 *
 */

public class MockAuthSystem {

    /*
       The list of user records
     */
	private List<MockAuthSystemEntry> userList;
	
	public MockAuthSystem() throws LDIFException, IOException, ParseException {
	
		//Compose the list of users here
		userList = new ArrayList<MockAuthSystemEntry>();
		composeMockAuthSystem();

	}
    /**
     * Populate the mock file based authentication system
     * by reading entries from the JSON config file
     *
     * The file is stored in src/main/resources/UserEntries.json
     * and is a JSON array of entries of the form:
     *
     *     {
     * 		"dn": "cn=alice,dc=solace,dc=com",
     * 		"memberOf": "publishers,ou=groups,dc=solace,dc=com",
     * 		"password": "alice"
     *     }
     *
     */
	private void composeMockAuthSystem() throws LDIFException, IOException, ParseException {
		
		/*
		 * Here compose the entries in our Mock Authentication
		 * System entries to test against
		 */

        InputStream is = MockAuthSystem.class.getResourceAsStream("/UserEntries.json");

        Object obj = new JSONParser().parse(new InputStreamReader(is,"UTF-8"));

        JSONArray jsonArray = (JSONArray) obj;

        Iterator iterator = jsonArray.iterator();


        while (iterator.hasNext())
        {
            Iterator<Map.Entry> iterator2 = ((Map) iterator.next()).entrySet().iterator();

            String dn = "";
            String password = "";
            String group = "";

            while (iterator2.hasNext()) {
                Map.Entry pair = iterator2.next();
                if (pair.getKey().equals("dn")) {
                    dn = (String) pair.getValue();
                }
                else if (pair.getKey().equals("password")) {
                    password = (String) pair.getValue();
                }
                else if (pair.getKey().equals("group")) {
                    group = (String) pair.getValue();
                }
            }

            MockAuthSystemEntry m = new MockAuthSystemEntry();
            Entry entry = new Entry("dn:"+dn,"memberOf:"+group);
            m.setDn(dn);
            m.setUserPassword(password);
            m.setEntry(entry);

            userList.add(m);
        }
	}

    /**
     * Search for a user in the authentication system and return
     * the complete user record
     *
     * @param user The user token to search in the authentication system
     *
     * @return The list of matching entries for this user token
     *
     */

	public List<Entry> searchMockAuthSystem(String user) {
		
		List<Entry> searchEntries = new ArrayList<Entry>();
		
		for (MockAuthSystemEntry m : userList) {
			if (m.getDn().contains(user)) {
				searchEntries.add(m.getEntry());
			}
		}

		return searchEntries;
	}

    /**
     * Validate the credentials for a supplied user
     *
     * @param user The user token to validate
     * @param password The password for the user to be validated
     *
     * @return true if the user is valid, false otherwise
     *
     */

	public Boolean validateUser(String user,String password) {
		
		for (MockAuthSystemEntry m : userList) {
			if (m.getDn().equals(user) && m.getUserPassword().equals(password)  ) {
				return true;
			}
		}
		
		return false;
	}

}
