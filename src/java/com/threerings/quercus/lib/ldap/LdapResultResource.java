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
import java.util.Iterator;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchResult;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;

import com.caucho.quercus.env.ArrayValue;
import com.caucho.quercus.env.ArrayValueImpl;
import com.caucho.quercus.env.LongValue;
import com.caucho.quercus.env.ResourceValue;
import com.caucho.quercus.env.StringValueImpl;
import com.caucho.quercus.env.Value;

public class LdapResultResource extends ResourceValue
{
    /**
     * Create new LdapResultResource the results of an LDAP search.
     *
     * @param results NamingEnumeration that is the result of an IntialDirContext.search().
     * @param attrTypesOnly If true, toArrayValue will only set return attribute types in entries,
     *        not their values.
     * @throws NamingException when there are errors iterating over the results NamingEnumeration,
     *         possibly due to something like an incomplete response from the LDAP server.
     */
    public LdapResultResource (NamingEnumeration results, boolean attrTypesOnly)
        throws NamingException
    {
        this._attrTypesOnly = attrTypesOnly;
        this._entries = new ArrayList<SearchResult>();
        while (results.hasMore()) {
            _entries.add((SearchResult) results.next());
        }
    }

    /**
     * Return an ArrayValue representation of the LDAP search results for consumption by PHP.
     *
     * @return ArrayValue with format specified by PHP's ldap_get_entries return value.
     * @throws NamingException when there is a problem iterating over NamingEnumerations of
     *         attributes or their values.
     */
    public ArrayValue toArrayValue () throws NamingException
    {
        ArrayValue entriesArray = new ArrayValueImpl();
        // PHP entriesArray["count"] as the number of entries.
        entriesArray.put(StringValueImpl.create("count"), LongValue.create(_entries.size()));

        Iterator<SearchResult> entriesIter = _entries.iterator();
        SearchResult entry;
        BasicAttributes attrs;
        ArrayValue entryAttrs;
        int entriesIdx = 0;

        NamingEnumeration<Attribute> attrsEnum;
        BasicAttribute attr;
        ArrayValue attrValues;
        Value attrName;
        int attrIdx;

        NamingEnumeration valuesEnum;
        int valueIdx;

        while (entriesIter.hasNext()) {
            entry = entriesIter.next();
            attrs = (BasicAttributes) entry.getAttributes();
            entryAttrs = new ArrayValueImpl();
            // PHP entriesArray[i]["count"] gets the number of attributes for entry number i.
            entryAttrs.put(StringValueImpl.create("count"), LongValue.create(attrs.size()));

            // PHP entriesArray[i]["dn"] gets the dn for entry number i.
            entryAttrs.put(StringValueImpl.create("dn"),
                StringValueImpl.create(entry.getNameInNamespace()));

            attrsEnum = attrs.getAll();
            attrIdx = 0;
            while (attrsEnum.hasMore()) {
                attr = (BasicAttribute) attrsEnum.next();
                attrName = StringValueImpl.create(attr.getID().toLowerCase());
                attrValues = new ArrayValueImpl();

                // Don't put in values and their count if attrsOnly was set to 1 during search.
                if (!_attrTypesOnly) {
                    // PHP entriesArray[i]["attr"]["count"] is the number of values in entry i.
                    attrValues.put(StringValueImpl.create("count"), LongValue.create(attr.size()));

                    valuesEnum = attr.getAll();
                    valueIdx = 0;
                    while (valuesEnum.hasMore()) {
                        // PHP entriesArray[i]["attr"][j] is the jth value of attr in entry i.
                        attrValues.put(LongValue.create(valueIdx),
                            StringValueImpl.create(valuesEnum.next().toString()));
                        valueIdx++;
                    }
                } else {
                    // When attrsOnly is 0, put in a value count of 0.
                    attrValues.put(StringValueImpl.create("count"), LongValue.create(0));
                }

                // PHP entriesArray[i]["attr"] is an array of values for attribute attr in entry i.
                entryAttrs.put(attrName, attrValues);

                // PHP entriesArray[i][j] is the name of the jth attribute in the ith entry.
                entryAttrs.put(LongValue.create(attrIdx), attrName);
                attrIdx++;
            }

            // PHP entriesArray[i] is an array of attributes for the ith entry.
            entriesArray.put(LongValue.create(entriesIdx), entryAttrs);
            entriesIdx++;
        }
        return entriesArray;
    }

    protected ArrayList<SearchResult> _entries;
    protected boolean _attrTypesOnly;
}
