/*
 * Copyright (c) 2007 Three Rings Design, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License version 2 as amended with additional clauses defined in the file
 * LICENSE in the main source directory.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the the
 * file LICENSE for additional details.
 *
 * @author Nick Barkas <snb@threerings.net>
 */

package com.threerings.quercus.lib.ldap;

import java.util.ArrayList;

import com.caucho.quercus.env.ArrayValue;
import com.caucho.quercus.env.ArrayValueImpl;
import com.caucho.quercus.env.BooleanValue;
import com.caucho.quercus.env.LongValue;
import com.caucho.quercus.env.StringValueImpl;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import junit.framework.JUnit4TestAdapter;

public class LdapModuleTest
{
    /** Get LDAP server port from test.properties, and instantiate connection. */
    @Before public void setUp ()
    {
        _port = System.getProperty("slapd_port");
        _connection = LdapModule.ldap_connect("localhost", _port);
    }

    /** Unbind from server. If we're not bound, nothing will happen. Reset constants to defaults. */
    @After public void tearDown ()
    {
        _connection.unbind();
        LdapModule.LDAP_OPT_REFERRALS = 0;
        LdapModule.LDAP_OPT_PROTOCOL_VERSION = 3;
    }

    @Test public void anonymousBind ()
    {
        /* XXX: The compiler is making me put empty strings here. Why isn't the @Optional annotation
         * letting me skip this? */
        BooleanValue result = LdapModule.ldap_bind(_connection, "", "");
        assertTrue("Trying anonymous bind", result.toBoolean());
    }

    @Test public void anonymousBindURIHostname ()
    {
        _connection = LdapModule.ldap_connect("ldap://localhost", _port);
        BooleanValue result = LdapModule.ldap_bind(_connection, "", "");
        assertTrue("Anonymous bind using ldap:// URI", result.toBoolean());
    }

    @Test public void anonymousBindWhitespaceURI ()
    {
        _connection = LdapModule.ldap_connect(" ldap://localhost", _port);
        BooleanValue result = LdapModule.ldap_bind(_connection, "", "");
        assertTrue("Anonymous bind using URI with leading whitespace", result.toBoolean());
    }

    @Test public void passwordlessBind ()
    {
        BooleanValue result = LdapModule.ldap_bind(_connection, "cn=foo,dc=example,dc=com", "");
        assertFalse("Binding with DN specified but empty password should fail", result.toBoolean());
    }

    @Test public void authenticatedBind ()
    {
        BooleanValue result = LdapModule.ldap_bind(_connection, "cn=Manager,dc=example,dc=com",
            "secret");
        assertTrue("Binding with manager DN and password", result.toBoolean());
    }

    @Test public void badPasswordBind ()
    {
        BooleanValue result = LdapModule.ldap_bind(_connection, "cn=Manager,dc=example,dc=com",
            "s3kr1t");
        assertFalse("Binding with manager DN and wrong password should fail", result.toBoolean());
    }

    @Test public void unbindUnbound ()
    {
        BooleanValue result = LdapModule.ldap_unbind(_connection);
        assertFalse("Unbinding should fail when not already bound", result.toBoolean());
    }

    @Test public void unbindNull ()
    {
        BooleanValue result = LdapModule.ldap_unbind(null);
        assertFalse("Unbinding should fail when link identifier is null", result.toBoolean());
    }

    @Test public void changeProtocolVersion ()
    {
        BooleanValue result = LdapModule.ldap_set_option(_connection, "LDAP_OPT_PROTOCOL_VERSION",
            2);
        assertTrue("Changing LDAP protocol version", result.toBoolean());
    }

    @Test public void changeConstant ()
    {
        BooleanValue result = LdapModule.ldap_set_option(_connection, "LDAP_DEREF_NEVER", 10);
        assertFalse("Trying to change LDAP_DEREF_NEVER should fail", result.toBoolean());
    }

    @Test public void changeInvalidOption ()
    {
        BooleanValue result = LdapModule.ldap_set_option(_connection, "LDAP_INVALID_OPTION", 10);
        assertFalse("Trying to change non-existent option should fail", result.toBoolean());
    }

    @Test public void searchGroups ()
    {
        // Make sure we fail right away if not bound.
        LdapResultResource searchResult = LdapModule.ldap_search(_connection,
            "ou=Groups,dc=example,dc=com", "objectClass=groupOfUniqueNames", null, 0, 0, 0, 0);
        assertNull("Search when not bound should fail", searchResult);

        LdapModule.ldap_bind(_connection, "", "");
        searchResult = LdapModule.ldap_search(_connection, "ou=Groups,dc=example,dc=com",
            "objectClass=groupOfUniqueNames", null, 0, 0, 0, 0);
        assertNotNull("Search for objectClass=groupOfUniqueNames should not return null",
            searchResult);

        ArrayValue resultArray = LdapModule.ldap_get_entries(_connection, searchResult);
        assertNotNull("Converting results to ArrayValue should not return null", resultArray);
        // There should be two groups of this objectClass.
        assertEquals(2, resultArray.get(StringValueImpl.create("count")).toInt());
    }

    @Test public void readJohn () {
        // Make sure we fail right away if not bound.
        LdapResultResource readResult = LdapModule.ldap_read(_connection,
            "uid=John,ou=People,dc=example,dc=com", "uid=john", null, 0, 0, 0, 0);
        assertNull("Search when not bound should fail", readResult);

        LdapModule.ldap_bind(_connection, "", "");
        // Let's only get the mail and cn attributes.
        ArrayList<String> attributes = new ArrayList<String>();
        attributes.add("mail");
        attributes.add("cn");
        readResult = LdapModule.ldap_read(_connection, "uid=John,ou=People,dc=example,dc=com",
            "uid=john", attributes, 1, 0, 0, 0);
        assertNotNull("Search for uid=john should not return null", readResult);

        ArrayValue resultArray = LdapModule.ldap_get_entries(_connection, readResult);
        assertNotNull("Converting results to ArrayValue should not return null", resultArray);
        assertEquals("There should be only one entry matching uid=john filter", 1,
            resultArray.get(StringValueImpl.create("count")).toInt());

        ArrayValue john = (ArrayValue) resultArray.getArray(LongValue.create(0));
        assertEquals("Verify John's DN is right", "uid=john,ou=People,dc=example,dc=com",
            john.get(StringValueImpl.create("dn")).toString());
        assertEquals("We should only have two attributes returned.", 2,
            john.get(StringValueImpl.create("count")).toInt());

        ArrayValueImpl johnMail = (ArrayValueImpl) john.getArray(StringValueImpl.create("mail"));
        assertEquals("John's mail should have no values since we set attrsOnly", "",
            johnMail.get(LongValue.create(0)).toString());
        assertEquals("John's mail should have a count of 0 since we set attrsOnly", 0,
            johnMail.get(StringValueImpl.create("count")).toInt());
    }

    public static junit.framework.Test suite ()
    {
        return new JUnit4TestAdapter(LdapModuleTest.class);
    }

    protected LdapLinkResource _connection;
    protected String _port;
}
