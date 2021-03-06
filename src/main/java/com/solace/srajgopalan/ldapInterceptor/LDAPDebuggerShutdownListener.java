package com.solace.srajgopalan.ldapInterceptor;

/*
 * Copyright 2010-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2017 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */

import com.unboundid.ldap.listener.LDAPListener;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import java.util.logging.Handler;

/**
 * This class provides a thread that will be started whenever the JVM running
 * the LDAP debugger is shut down.  It will be used to ensure that the LDAP
 * listener and log handler are properly closed.
 */
@NotMutable()
@ThreadSafety(level= ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPDebuggerShutdownListener
        extends Thread
{
    // The log handler that will be closed.
    private final Handler logHandler;

    // The LDAP listener that will be closed.
    private final LDAPListener listener;



    /**
     * Creates a new shutdown listener that will shut down the LDAP listener and
     * close the log handler when the JVM is shutting down.
     *
     * @param  listener    The LDAP listener to be shut down.
     * @param  logHandler  The log handler to be closed.
     */
    LDAPDebuggerShutdownListener(final LDAPListener listener,
                                 final Handler logHandler)
    {
        this.listener   = listener;
        this.logHandler = logHandler;
    }



    /**
     * Starts this thread to shut down the listener and close the log handler.
     */
    @Override()
    public void run()
    {
        listener.shutDown(true);
        logHandler.close();
    }
}

