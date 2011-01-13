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

import javax.naming.directory.SearchControls;
import javax.naming.NamingException;

import com.caucho.quercus.env.ArrayValue;
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
import static org.junit.Assert.fail;
import junit.framework.JUnit4TestAdapter;

public class LdapLinkResourceTest
{
    /** Get LDAP server port from test.properties, and instantiate connection. */
    @Before public void setUp ()
    {
        String port = System.getProperty("slapd_port");
        _connection = new LdapLinkResource("ldap://localhost:" + port);
    }

    /** Unbind from server. If we're not bound, nothing will happen. */
    @After public void tearDown ()
    {
        _connection.unbind();
    }

    @Test public void anonymousBind ()
    {
        assertTrue("Trying anonymous bind", _connection.simpleBind("", ""));
    }

    @Test public void passwordlessBind ()
    {
        assertFalse("Binding with DN specified but empty password should fail",
                    _connection.simpleBind("cn=john,dc=example,dc=com", ""));
    }

    @Test public void authenticatedBind ()
    {
        assertTrue("Binding with manager DN and password",
                   _connection.simpleBind("cn=Manager,dc=example,dc=com", "secret"));
    }

    @Test public void badPasswordBind ()
    {
        assertFalse("Binding with manager DN and wrong password",
                   _connection.simpleBind("cn=Manager,dc=example,dc=com", "s3kr1t"));
    }

    @Test public void unbindUnbound ()
    {
        assertFalse("Unbinding should fail when not already bound", _connection.unbind());
    }

    /* Note that this also is testing LdapResultResource.toArrayValue() fairly extensively. */
    @Test public void searchSally ()
    {
        _connection.simpleBind("", "");
        LdapResultResource searchResult = _connection.search("ou=People,dc=example,dc=com",
            "uid=sally", null, 0, 0, 0, 0, SearchControls.SUBTREE_SCOPE);
        assertNotNull("Search for uid=sally should not return null", searchResult);
        try {
            ArrayValue resultArray = searchResult.toArrayValue();
            assertEquals("Only one entry should be returned on search for uid=sally", 1,
                resultArray.get(StringValueImpl.create("count")).toInt());

            ArrayValue sally = (ArrayValue) resultArray.getArray(LongValue.create(0));
            assertEquals("uid=sally,ou=People,dc=example,dc=com",
                sally.get(StringValueImpl.create("dn")).toString());
            assertEquals("Sally should have 11 attributes", 11,
                sally.get(StringValueImpl.create("count")).toInt());

            ArrayValue sallyShell =
                (ArrayValue) sally.getArray(StringValueImpl.create("loginshell"));
            assertEquals("Sally's shell should be /bin/tcsh", "/bin/tcsh",
                sallyShell.get(LongValue.create(0)).toString());

            ArrayValue sallyMail = (ArrayValue) sally.getArray(StringValueImpl.create("mail"));
            assertEquals("Sally has two email addresses", 2,
                sallyMail.get(StringValueImpl.create("count")).toInt());

            ArrayValue sallyFoo = (ArrayValue) sally.getArray(StringValueImpl.create("foo"));
            assertEquals("Make sure there are no values for non-existent attribute foo", 0,
                sallyFoo.get(StringValueImpl.create("count")).toInt());
        } catch (NamingException e) {
            fail("searchResult.toArrayValue() for uid=sally search shouldn't throw an Exception.");
        }
    }

    @Test public void searchNonExistent ()
    {
        _connection.simpleBind("", "");
        LdapResultResource searchResult = _connection.search("ou=People,dc=example,dc=com",
            "uid=fred", null, 0, 0, 0, 0, SearchControls.SUBTREE_SCOPE);
        assertNotNull("Search for uid=fred should not return null", searchResult);
        try {
            ArrayValue resultArray = searchResult.toArrayValue();
            assertEquals("No entries should be returned on search for uid=fred", 0,
                resultArray.get(StringValueImpl.create("count")).toInt());
        } catch (NamingException e) {
            fail("searchResult.toArrayValue() for uid=fred search shouldn't throw an Exception.");
        }
    }

    public static junit.framework.Test suite ()
    {
        return new JUnit4TestAdapter(LdapLinkResourceTest.class);
    }

    protected LdapLinkResource _connection;
}
