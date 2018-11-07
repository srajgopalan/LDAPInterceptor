package com.solace.srajgopalan.ldapInterceptor;


import com.unboundid.ldap.listener.LDAPListenerClientConnection;
import com.unboundid.ldap.listener.LDAPListenerRequestHandler;
import com.unboundid.ldap.protocol.*;
import com.unboundid.ldap.sdk.*;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * This class provides a simple LDAP listener request handler
 * implementation that accepts LDAP search and bind requests
 * and interfaces with a backend authentication system
 * for performing the actual authentication request
 */

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CustomAuthRequestHandler
       extends LDAPListenerRequestHandler
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6199105854736880833L;


  // The protocol ops that will be used in responses.
  private AddResponseProtocolOp addResponseProtocolOp;
  private BindResponseProtocolOp bindResponseProtocolOp;
  private CompareResponseProtocolOp compareResponseProtocolOp;
  private DeleteResponseProtocolOp deleteResponseProtocolOp;
  private ExtendedResponseProtocolOp extendedResponseProtocolOp;
  private ModifyResponseProtocolOp modifyResponseProtocolOp;
  private ModifyDNResponseProtocolOp modifyDNResponseProtocolOp;
  private List<SearchResultEntryProtocolOp> searchEntryProtocolOps;
  private List<SearchResultReferenceProtocolOp> searchReferenceProtocolOps;
  private SearchResultDoneProtocolOp searchResultDoneProtocolOp;

  // The connection that will be used to communicate with the client.
  private final LDAPListenerClientConnection clientConnection;
  
  /*
   * Instantiate the mock file-based authentication system
   * Remove the reference when interfacing with any other
   * authentication system
   */
  
   //The mock authentication database
   private static MockAuthSystem mockAuthSystem;

   static {
       //Initialize our mock file based authentication system ONCE
       // for all listeners

       try {
           mockAuthSystem = new MockAuthSystem();
       } catch (Exception e) {
           System.out.println("Unable to initialise our file based authentication system!");
           e.printStackTrace();
           System.exit(-1);
       }
   }
  
  /**
   * Creates a new instance of this LDAP response request handler 
   * @throws LDIFException 
   */
  public CustomAuthRequestHandler() 
  {

      clientConnection = null;

  }

  /**
   * Creates a new instance of this custom response request handler using the
   * information of the provided handler and the given client connection.
   *
   * @param  h  The request handler from which to take the responses.
   * @param  c  The connection to use to communicate with the client.
   */
  private CustomAuthRequestHandler(final CustomAuthRequestHandler h,
               final LDAPListenerClientConnection c)  {

    addResponseProtocolOp      = h.addResponseProtocolOp;
    bindResponseProtocolOp     = h.bindResponseProtocolOp;
    compareResponseProtocolOp  = h.compareResponseProtocolOp;
    deleteResponseProtocolOp   = h.deleteResponseProtocolOp;
    extendedResponseProtocolOp = h.extendedResponseProtocolOp;
    modifyResponseProtocolOp   = h.modifyResponseProtocolOp;
    modifyDNResponseProtocolOp = h.modifyDNResponseProtocolOp;
    searchEntryProtocolOps     = h.searchEntryProtocolOps;
    searchReferenceProtocolOps = h.searchReferenceProtocolOps;
    searchResultDoneProtocolOp = h.searchResultDoneProtocolOp;

    clientConnection = c;

  }

  /**
   * {@inheritDoc}
   */
  @Override()
  public CustomAuthRequestHandler newInstance(
              final LDAPListenerClientConnection connection)
         throws LDAPException
  {
      return new CustomAuthRequestHandler(this, connection);

  }

  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processAddRequest(final int messageID,
                                       final AddRequestProtocolOp request,
                                       final List<Control> controls)
  {
		
	/*
	 *  Implement the LDAP Add method
	 *  Here a canned success response is returned
	 */
    
    ResultCode rc = ResultCode.SUCCESS;
	String diagnosticMessage = "";
	List<String> referralURLs = null;
	String matchedDN = null;
	
	addResponseProtocolOp = new AddResponseProtocolOp(rc.intValue(), matchedDN,
	         diagnosticMessage, referralURLs);
	  
    return new LDAPMessage(messageID, addResponseProtocolOp,
         Collections.<Control>emptyList());
  }

  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processBindRequest(final int messageID,
                                        final BindRequestProtocolOp request,
                                        final List<Control> controls)
  {
	    
	  System.out.println("In processBindRequest - This contains the custom code to validate the bind request with the backend");
	  	   
	/* 
	 * You can extract the username and password from the request token as below:
	 */
	
	String username = request.getBindDN().toString();
	String password = request.getSimplePassword().toString();

	System.out.println("The bind DN is:"+username);
	System.out.println("The bind password is:"+password);
	
	/*
	  *  INSERT CUSTOM CODE HERE
	  *  Perform user authentication for the bind operation
	  *  Validate the username and password against the
	  *  backend authentication system
	  *  and return the response as an LDAP message
	  *  
	  *  In the example we validate the bind against
	  *  a Mock file based backend
	  */
	
	ResultCode rc = ResultCode.SUCCESS;
	
	try {	
		Boolean isValid = mockAuthSystem.validateUser(username, password);
		
		if(isValid) {
			System.out.println("The user is valid");
			rc = ResultCode.SUCCESS;
		}else {
			System.out.println("The user is invalid");
			rc = ResultCode.INVALID_CREDENTIALS;
		}
	}
	catch (Exception e) {
			System.out.println("Caught Exception:"+e.getCause() + e.getLocalizedMessage());
	}
	
	String diagnosticMessage = "This is a sample bind message";
	List<String> referralURLs = null;
	String matchedDN = null;
	
	bindResponseProtocolOp = new BindResponseProtocolOp(rc.intValue(), matchedDN,
	         diagnosticMessage, referralURLs, null);
	
    return new LDAPMessage(messageID, bindResponseProtocolOp,
         Collections.<Control>emptyList());
      
  }

  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processCompareRequest(final int messageID,
                          final CompareRequestProtocolOp request,
                          final List<Control> controls)
  {
	  /*
		 *  Implement the LDAP Compare method
		 *  Here a canned success response is returned
		 */
	    
	    ResultCode rc = ResultCode.SUCCESS;
		String diagnosticMessage = "";
		List<String> referralURLs = null;
		String matchedDN = null;
		
		compareResponseProtocolOp = new CompareResponseProtocolOp(rc.intValue(), matchedDN,
		         diagnosticMessage, referralURLs);
	  
	  return new LDAPMessage(messageID, compareResponseProtocolOp,
         Collections.<Control>emptyList());
  }

  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processDeleteRequest(final int messageID,
                                          final DeleteRequestProtocolOp request,
                                          final List<Control> controls)
  {

	/*
	 *  Implement the LDAP Delete method
	 *  Here a canned success response is returned
	 */
    
    ResultCode rc = ResultCode.SUCCESS;
	String diagnosticMessage = "";
	List<String> referralURLs = null;
	String matchedDN = null;
	
	deleteResponseProtocolOp = new DeleteResponseProtocolOp(rc.intValue(), matchedDN,
	         diagnosticMessage, referralURLs);
	
	return new LDAPMessage(messageID, deleteResponseProtocolOp,
       Collections.<Control>emptyList());
  }

  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processExtendedRequest(final int messageID,
                          final ExtendedRequestProtocolOp request,
                          final List<Control> controls)
  {
	
		/*
		 *  Implement the Extended LDAP Delete method
		 *  Here a canned success response is returned
		 */
	    
	    ResultCode rc = ResultCode.SUCCESS;
		String diagnosticMessage = "";
		List<String> referralURLs = null;
		String matchedDN = null;
		
		extendedResponseProtocolOp = new ExtendedResponseProtocolOp(rc.intValue(), matchedDN,
		         diagnosticMessage, referralURLs,null,null);
  	  
    return new LDAPMessage(messageID, extendedResponseProtocolOp,
         Collections.<Control>emptyList());
  }

  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processModifyRequest(final int messageID,
                                          final ModifyRequestProtocolOp request,
                                          final List<Control> controls)
  {

	/*
	 *  Implement the LDAP Modify method
	 *  Here a canned success response is returned
	 */
    
    ResultCode rc = ResultCode.SUCCESS;
	String diagnosticMessage = "";
	List<String> referralURLs = null;
	String matchedDN = null;
	
	modifyResponseProtocolOp = new ModifyResponseProtocolOp(rc.intValue(), matchedDN,
	         diagnosticMessage, referralURLs);
		
    return new LDAPMessage(messageID, modifyResponseProtocolOp,
         Collections.<Control>emptyList());
  }

  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          final ModifyDNRequestProtocolOp request,
                          final List<Control> controls)
  {

	/*
	 *  Implement the LDAP Modify DN Request method
	 *  Here a canned success response is returned
	 */
    
    ResultCode rc = ResultCode.SUCCESS;
	String diagnosticMessage = "";
	List<String> referralURLs = null;
	String matchedDN = null;
	
	modifyDNResponseProtocolOp = new ModifyDNResponseProtocolOp(rc.intValue(), matchedDN,
	         diagnosticMessage, referralURLs);
	  
    return new LDAPMessage(messageID, modifyDNResponseProtocolOp,
         Collections.<Control>emptyList());
  }

  /**
   * {@inheritDoc}
   */
  @SuppressWarnings("unused")
@Override()
  public LDAPMessage processSearchRequest(final int messageID,
                                          final SearchRequestProtocolOp request,
                                          final List<Control> controls)
  {  
	  System.out.println("Inside processSearchRequest - this searches the backend authentication system " +
              "for user credentials");
	  
	/*
	 * This is the LDAP search operation which is used to 
	 * check if the user object exists in the backend
	 * authentication system such as IDAM
	 */
	   
	/*
	 * Compose Search Entries here
	 * by searching the backend authentication system
	 * for the username - return group membership
	 * attributes, used for LDAP Authorization in Solace
	 * 
	 * In this example a search entry is performed on
	 * the mock authentication backend
	 */
	  
	 try { 
	
	 //Extract the token from the request
	 String userToken = request.getFilter().getAssertionValue(); 
	 String baseDN = request.getBaseDN();
	 
	 String DN = "cn="+userToken+","+baseDN;

	 //Invoke IDAM and perform search
	 //and get a result of search entries
     // Here we just use the mock list of user entries
	
	List<Entry> searchEntries = mockAuthSystem.searchMockAuthSystem(userToken);
	
	 
    if ((searchEntries == null) || searchEntries.isEmpty())
    {
        System.out.println("The search is empty..");
    	searchEntryProtocolOps = Collections.emptyList();
    }
    else
    {
      
      final ArrayList<SearchResultEntryProtocolOp> l =
           new ArrayList<SearchResultEntryProtocolOp>(searchEntries.size());
      
      for (final Entry e : searchEntries)
      {
        l.add(new SearchResultEntryProtocolOp(e));
      }
      
      searchEntryProtocolOps = Collections.unmodifiableList(l);
    }

    /*
     * Compose Search references here
     * Only valid when you want to refer
     * the LDAP search to another LDAP server
     * 
     * here it is set to null as there 
     * are no references
     * 
     */
    
    Collection<SearchResultReference> searchReferences = null;
    
	if ((searchReferences == null) || searchReferences.isEmpty())
    {
      searchReferenceProtocolOps = Collections.emptyList();
    }
    else
    {
      final ArrayList<SearchResultReferenceProtocolOp> l =
           new ArrayList<SearchResultReferenceProtocolOp>(
                searchReferences.size());
      for (final SearchResultReference r : searchReferences)
      {
        l.add(new SearchResultReferenceProtocolOp(r));
      }

      searchReferenceProtocolOps = Collections.unmodifiableList(l);
    }
	
	//Response Composed, now send the search entry and references back
       
    for (final SearchResultEntryProtocolOp e : searchEntryProtocolOps)
    {
      try
      {
        clientConnection.sendSearchResultEntry(messageID, e);
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
      }
    }

    for (final SearchResultReferenceProtocolOp r : searchReferenceProtocolOps)
    {
      try
      {
        clientConnection.sendSearchResultReference(messageID, r);
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
      }
    }
	
	/*
	 *  Compose the search result here
	 *  based on the above search entry
	 *  
	 *  Here we are returning a Success
	 *  based on the above canned result
	 */
     
    ResultCode rc = ResultCode.SUCCESS;
	String diagnosticMessage = "This is a sample search message";
	List<String> referralURLs = null;
	String matchedDN = null;
	
    searchResultDoneProtocolOp = new SearchResultDoneProtocolOp(rc.intValue(), matchedDN,
            diagnosticMessage, referralURLs);
    
	 } catch (Exception e) {
		 e.printStackTrace();
	 }
    
    return new LDAPMessage(messageID, searchResultDoneProtocolOp,
    		Collections.<Control>emptyList());
  }
  
}