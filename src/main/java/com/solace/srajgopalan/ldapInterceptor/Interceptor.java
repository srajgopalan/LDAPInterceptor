package com.solace.srajgopalan.ldapInterceptor;


import com.unboundid.ldap.listener.LDAPDebuggerRequestHandler;
import com.unboundid.ldap.listener.LDAPListener;
import com.unboundid.ldap.listener.LDAPListenerConfig;
import com.unboundid.ldap.listener.LDAPListenerRequestHandler;
import com.unboundid.util.MinimalLogFormatter;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;

public class Interceptor {
    LDAPDebuggerShutdownListener shutdownListener;

	public static void main(String[] args) throws Exception {
		
		Interceptor ic = new Interceptor();
		
		
		if (args == null || args.length != 1) {
		
			System.out.println("Usage: Interceptor [port]");
			System.out.println();
            System.exit(-1);
		}
		
		ic.runInterceptor(Integer.parseInt( args[0] ));
		
	}

	public void runInterceptor(int port) throws Exception {
		// Create an instance of our Custom Authentication
		// Request Handler

		// This will handle all the LDAP server requests from Solace
		
		CustomAuthRequestHandler customAuthRequestHandler =
				new CustomAuthRequestHandler();
		
		final Handler logHandler;
		logHandler = new ConsoleHandler();
		logHandler.setLevel(Level.ALL);
		logHandler.setFormatter(new MinimalLogFormatter(
				MinimalLogFormatter.DEFAULT_TIMESTAMP_FORMAT, false, false, true));

		// Create the debugger request handler that will be used to write the
		// debug output.
		LDAPListenerRequestHandler requestHandler =
			 new LDAPDebuggerRequestHandler(logHandler, customAuthRequestHandler);

		// LDAP listen port
		int listenPort = port;

		// Create and start an LDAP listener
		LDAPListenerConfig listenerConfig = new LDAPListenerConfig(listenPort,
				requestHandler);
		LDAPListener listener = new LDAPListener(listenerConfig);
		listener.startListening();
		System.out.println("Intercepting...");

	    // Note that at this point, the listener will continue running in a
	    // separate thread, so we can return from this thread without exiting the
	    // program.  However, we'll want to register a shutdown hook so that we can
	    // close the logger.

	    shutdownListener = new LDAPDebuggerShutdownListener(listener, logHandler);
	    Runtime.getRuntime().addShutdownHook(shutdownListener);

	}
	  /**
	   * Indicates that the associated listener should shut down.
	   */
	  public void shutDown()
	  {
	    Runtime.getRuntime().removeShutdownHook(shutdownListener);
	    shutdownListener.run();
	  }


}
