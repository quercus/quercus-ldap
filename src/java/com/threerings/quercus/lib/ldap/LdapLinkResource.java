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

import java.util.Hashtable;
import java.util.List;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;

import com.caucho.quercus.env.ResourceValue;

public class LdapLinkResource extends ResourceValue
{
    /**
     * Create a new LdapLinkResource.
     *
     * @param uri URI of LDAP server.
     */
    public LdapLinkResource (String uri)
    {
        this._uri = uri;
    }

    /**
     * Search for the specified filter on the directory.
     *
     * @param baseDN Base DN for the directory.
     * @param filter LDAP search filter.
     * @param attributes ArrayValue of the desired attributes to fetch from the entry. Note that the
     *        DN is always included. All attributes are fetched if null.
     * @param attrsOnly Retrieve only attribute types if 1, values and types if 0.
     * @param sizeLimit Limit the number of entries fetched. Setting to 0 means no limit.
     * @param timeLimit Maximum number of seconds to spend on the search. No limit if set to 0.
     * @param deref Specifies how aliases should be handled during the search.
     * @param scope The scope to search under. Can be SearchControls.OBJECT_SCOPE, ONELEVEL_SCOPE,
     *        or SUBTREE_SCOPE.
     * @return LdapResultResource identifier of the search result, or null on error.
     */
    public LdapResultResource search (String baseDN, String filter, List<String> attributes,
                                      int attrsOnly, long sizeLimit, int timeLimit, int deref,
                                      int scope)
    {
        // Give up if we're not bound.
        if (_ctx == null) {
            return null;
        }

        boolean attrTypesOnly = (attrsOnly == 1);

        // Convert List of attributes to a String array. If List is null, leave attrArray null.
        String[] attrArray = null;
        if (attributes != null) {
            // Always include the dn in search results.
            if (!attributes.contains("dn")) {
                attributes.add("dn");
            }
            attrArray = (String[]) attributes.toArray(new String[0]);
        }

        // Set up all the options for the search. XXX: do we want true or false for retobj argument?
        boolean doDeref = ((deref == LdapModule.LDAP_DEREF_SEARCHING) ||
            (deref == LdapModule.LDAP_DEREF_ALWAYS));
        SearchControls ctls = new SearchControls(scope, sizeLimit, timeLimit, attrArray, true,
            doDeref);

        try {
            NamingEnumeration answer = _ctx.search(baseDN, filter, ctls);
            return new LdapResultResource(answer, attrTypesOnly);
        } catch (NamingException e) {
            return null;
        }
    }

    /**
     * Perform a simple bind to an LDAP server, saving the context.
     *
     * @param dn Distinguished name to bind as. If this is an empty string, an anonymous bind will
     *        be attempted.
     * @param password Password associated with dn. If it and dn are empty strings, an anonymous
     *        bind will be attempted. If dn is not blank and this is, simpleBind() will return
     *        false.
     * @return true if bind is successful, false otherwise.
     */
    public boolean simpleBind (String dn, String password)
    {
        Hashtable<String, String> env = new Hashtable<String, String>();
        // Set up environment properties needed for binding.
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, _uri);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put("java.naming.ldap.version", Integer.toString(LdapModule.LDAP_OPT_PROTOCOL_VERSION));
        if (LdapModule.LDAP_OPT_REFERRALS == 1) {
            env.put(Context.REFERRAL, "follow");
        } else {
            env.put(Context.REFERRAL, "ignore");
        }

        if (dn.length() > 0) {
            if (password.length() == 0) {
                /* If there is a dn but the password is empty, bail out now in case we happen to
                 * be connecting to a server that treats binds with a valid DN and no password as an
                 * anonymous bind. */
                return false;
            }
            env.put(Context.SECURITY_PRINCIPAL, dn);
            env.put(Context.SECURITY_CREDENTIALS, password);
        }

        try {
            _ctx = new InitialDirContext(env);
        } catch (NamingException e) {
            //e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Unbind from LDAP server.
     * @return true if successful, false if not.
     */
    public boolean unbind ()
    {
        // Can't unbind if we never got bound in the first place!
        if (_ctx == null) {
            return false;
        }

        try {
            _ctx.close();
        } catch (NamingException e) {
            //e.printStackTrace();
            return false;
        }
        return true;
    }

    protected InitialDirContext _ctx;
    protected String _uri;
}
