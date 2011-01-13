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

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import javax.naming.directory.SearchControls;
import javax.naming.NamingException;

import com.caucho.quercus.annotation.Optional;
import com.caucho.quercus.annotation.ReturnNullAsFalse;
import com.caucho.quercus.env.ArrayValue;
import com.caucho.quercus.env.BooleanValue;
import com.caucho.quercus.module.AbstractQuercusModule;
import com.caucho.quercus.UnimplementedException;

/**
 * A (partial) implementation of PHP's LDAP module.
 *
 * Most methods in this class are not yet implemented. In fact, many PHP LDAP functions and
 * constants have not even been added to this class. Right now pretty much all that is supported is
 * binding to an LDAP server, and unbinding. This is usually good enough for just doing LDAP
 * authentication.
 */
public class LdapModule extends AbstractQuercusModule
{
    /** If set to 0 (default), referrals will be ignored. If 1, they will be followed. */
    public static int LDAP_OPT_REFERRALS                = 0;

    /** LDAP protocol version to use. Can be set to 3 (default) or 2. */
    public static int LDAP_OPT_PROTOCOL_VERSION         = 3;

    // Alias dereferencing behaviors. These can not be changed with ldap_set_option().
    public static final int LDAP_DEREF_NEVER            = 0;
    public static final int LDAP_DEREF_SEARCHING        = 1;
    public static final int LDAP_DEREF_FINDING          = 2;
    public static final int LDAP_DEREF_ALWAYS           = 3;

    /**
     * Add entry to LDAP directory.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @param dn The distinguished name of an LDAP entry.
     * @param entry Map associating LDAP attributes to their values.
     * @return BooleanValue.TRUE if successful, BooleanValue.FALSE otherwise.
     */
    public static BooleanValue ldap_add (LdapLinkResource linkIdentifier, String dn, Map entry)
    {
        throw new UnimplementedException("ldap_add");
    }

    /**
     * Binds to an LDAP directory.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @param bindRdn RDN to bind as. If omitted attempt an anonymous bind.
     * @param bindPassword password corresponding to bindRdn.
     * @return True if successful, false otherwise.
     */
    public static BooleanValue ldap_bind (LdapLinkResource linkIdentifier, @Optional String bindRdn,
                                          @Optional String bindPassword)
    {
        boolean success = linkIdentifier.simpleBind(bindRdn, bindPassword);
        return BooleanValue.create(success);
    }

    /**
     * Connect to an LDAP server.
     *
     * @param hostname Host name of the LDAP server. Can also be an ldap:// or ldaps:// URI.
     * @param port TCP port LDAP server runs on. If omitted defaults to 389, or 636 if hostname is
     *        is an ldaps:// URI.
     * @return LdapLinkResource object, or null if unable to connect to host.
     */
    @ReturnNullAsFalse
    public static LdapLinkResource ldap_connect (String hostname, @Optional String port)
    {
        // PHP apparently expects this to work with leading and/or trailing whitespace. Gah.
        String uri = hostname.trim();
        // If port is unspecified, set it to 389. Or 636 if hostname implies we want SSL.
        if (port == "") {
            if (uri.startsWith("ldaps://")) {
                port = "636";
            } else {
                port = "389";
            }
        }
        uri = uri + ":" + port;

        /* Prepend ldap:// (or ldaps:// if port is 636) if those aren't already at the beginning of
         * the hostname. */
        if (!(uri.startsWith("ldaps://")) && !(uri.startsWith("ldap://"))) {
            if (port == "636") {
                uri = "ldaps://" + uri;
            } else {
                uri = "ldap://" + uri;
            }
        }

        // XXX: should make sure ldap server is there, and return null if it's not.
        return new LdapLinkResource(uri);
    }

    /**
     * Get all entries for a given search result as an ArrayValue.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @param resultIdentifier Identifier of the LDAP result we're interested in.
     * @return ArrayValue containing all entries and their attributes from resultIdentifier, or null
     *         on error. Note that LDAP attributes are always all lower case in this ArrayValue. The
     *         ArrayValue has the following structure, in PHP array syntax:
     *
     *         return_val["count"] :            number of entries in result.
     *         return_val[i] :                  ArrayValue containing details of the ith entry.
     *         return_val[i]["dn"] :            DN of the ith entry.
     *         return_val[i]["count"] :         Number of attributes in the ith entry.
     *         return_val[i][j] :               Name of jth attribute in ith entry.
     *         return_val[i]["attr"]["count"] : Number of values for attr in ith entry.
     *         return_val[i]["attr"][j] :       jth value of attr in ith entry.
     */
    @ReturnNullAsFalse
    public static ArrayValue ldap_get_entries (LdapLinkResource linkIdentifier,
                                               LdapResultResource resultIdentifier)
    {
        // XXX: linkIdentifier does not seem needed here. Why does PHP use it?

        // Fail rather than NPE if resultIdentifier is null.
        if (resultIdentifier == null) {
            return null;
        }

        try {
            return resultIdentifier.toArrayValue();
        } catch (NamingException e) {
            return null;
        }
    }

    /**
     * Modify an LDAP entry.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @param dn The distinguished name of an LDAP entry to modify.
     * @param entry Map of LDAP attributes and their values, same as used in ldap_add().
     * @return True on success, false otherwise.
     */
    public static BooleanValue ldap_modify (LdapLinkResource linkIdentifier, String dn,
                                            Map entry)
    {
        throw new UnimplementedException("ldap_modify");
    }

    /**
     * Search for the specified filter on the directory within the given object itself only.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @param baseDN Base DN for the directory.
     * @param filter LDAP search filter.
     * @param attributes ArrayValue of the desired attributes to fetch from the entry. Note that the
     *        DN is always included. All attributes are fetched if omitted.
     * @param attrsOnly Retrieve only attribute types if true, values and types if false. If
     *        omitted types and values are fetched.
     * @param sizeLimit Limit the number of entries fetched. Setting to 0 means no limit, which is
     *        the default behavior if argument is omitted.
     * @param timeLimit Maximum number of seconds to spend on the search. No limit if set to 0,
     *        which is the default behavior if argument is omitted.
     * @param deref Specifies how aliases should be handled during the search. If omitted aliases
     *        are never dereferenced.
     * @return LdapResultResource identifier of the search result, or null on error.
     */
    @ReturnNullAsFalse
    public static LdapResultResource ldap_read (LdapLinkResource linkIdentifier, String baseDN,
                                                String filter, @Optional List<String> attributes,
                                                @Optional("0") int attrsOnly,
                                                @Optional("0") long sizeLimit,
                                                @Optional("0") int timeLimit,
                                                @Optional("0") int deref)
    {
        // Fail instead of NPE if someone tries to search before connecting.
        if (linkIdentifier == null) {
            return null;
        }
        return linkIdentifier.search(baseDN, filter, attributes, attrsOnly, sizeLimit, timeLimit,
            deref, SearchControls.OBJECT_SCOPE);
    }

    /**
     * Search for the specified filter on the directory within the object and all its descendants.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @param baseDN Base DN for the directory.
     * @param filter LDAP search filter.
     * @param attributes ArrayValue of the desired attributes to fetch from the entry. Note that the
     *        DN is always included. All attributes are fetched if omitted.
     * @param attrsOnly Retrieve only attribute types if 1, values and types if 0. If omitted types
     *        and values are fetched.
     * @param sizeLimit Limit the number of entries fetched. Setting to 0 means no limit, which is
     *        the default behavior if argument is omitted.
     * @param timeLimit Maximum number of seconds to spend on the search. No limit if set to 0,
     *        which is the default behavior if argument is omitted.
     * @param deref Specifies how aliases should be handled during the search. If omitted aliases
     *        are never dereferenced.
     * @return LdapResultResource identifier of the search result, or null on error.
     */
    @ReturnNullAsFalse
    public static LdapResultResource ldap_search (LdapLinkResource linkIdentifier, String baseDN,
                                                  String filter, @Optional List<String> attributes,
                                                  @Optional("0") int attrsOnly,
                                                  @Optional("0") long sizeLimit,
                                                  @Optional("0") int timeLimit,
                                                  @Optional("0") int deref)
    {
        // Fail instead of NPE if someone tries to search before connecting.
        if (linkIdentifier == null) {
            return null;
        }
        return linkIdentifier.search(baseDN, filter, attributes, attrsOnly, sizeLimit, timeLimit,
            deref, SearchControls.SUBTREE_SCOPE);
    }

    /**
     * Set the value of the given static class field representing an LDAP option to a new value.
     * These fields can actually be set directly with an assignment, but this method is provided for
     * compatibility.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @param option Name of the field to change.
     * @param newVal New value to set.
     * @return True if successful, false otherwise.
     */
    public static BooleanValue ldap_set_option (LdapLinkResource linkIdentifier, String option,
                                                int newVal)
    {
        /* XXX: what is the linkIdentifier argument for? Does php-ldap actually set these constants
         * on a per connection basis? */

        // Use reflection to change the value of the field named option to newVal.
        Class myClass = LdapModule.class;
        try {
            Field f = myClass.getField(option);
            f.setInt(myClass, newVal);
        } catch (Exception e) {
            /* The above could throw an IllegalAccessException or NoSuchFieldException. Either way,
             * we have failed. */
            return BooleanValue.create(false);
        }
        return BooleanValue.create(true);
    }

    /**
     * Start TLS for the given connection.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @return True if successful, false otherwise.
     */
    public static BooleanValue ldap_start_tls (LdapLinkResource linkIdentifier)
    {
        throw new UnimplementedException("ldap_start_tls");
    }

    /**
     * Unbind from LDAP directory.
     *
     * @param linkIdentifier LdapLinkResource returned by ldap_connect().
     * @return True if successful, false otherwise.
     */
    public static BooleanValue ldap_unbind (LdapLinkResource linkIdentifier)
    {
        // Avoid NPEs from this being called on non-existent linkIdentifiers.
        if (linkIdentifier == null) {
            return BooleanValue.create(false);
        }
        boolean success = linkIdentifier.unbind();
        return BooleanValue.create(success);
    }
}
