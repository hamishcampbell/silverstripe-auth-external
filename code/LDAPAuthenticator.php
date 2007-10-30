<?php

/**
 * LDAP authenticator and controller
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 */


class LDAPPosixAccount {
   /**
    * LDAP connection handle
    **/
   protected static $ds;
   
   /**
    * Result of the last authentication action
    **/
   protected static $success = false;
   
   /**
    * Message from the last authentication action
    **/
   protected static $message = "You have been logged in based on your LDAP credentials";     

   /**
	 * Get the success of the last authentication attempt
	 *
	 * @return bool success
	 */              
   public static function getLDAPAuthSuccess() {
       return self::$success;
   }
   
   /**
	 * Get the message of the last authentication attempt
	 *
	 * @return string message
	 */                 
   public static function getLDAPAuthMessage() {
       return self::$message;
   }
   
    /**
     * Does an ldap connect and binds as the guest user or as the optional dn.
     *
     * @return boolean on success, error message on fail.
     */
    public function Connect() {   
        // Revert to the PHP error handler to prevent the SilverStripe
        // error handler from interfering
        restore_error_handler();

        /* Connect to the LDAP server. */
        self::$ds = @ldap_connect(LDAPAuthenticator::getLDAPServer(), LDAPAUthenticator::getLDAPPort());
        if (!self::$ds) {
            Debug::loadErrorHandlers();
            return 'Failed to connect to LDAP server.';
        }

        if (!ldap_set_option(self::$ds, LDAP_OPT_PROTOCOL_VERSION,
                             LDAPAuthenticator::getLDAPVersion())) {
             Debug::loadErrorHandlers();
             return sprintf('Set LDAP protocol version to %d failed: [%d] %s',
                            LDAPAuthenticator::getLDAPVersion(),
                            ldap_errno(self::$ds),
                            ldap_error(self::$ds));
        }
        
        if (LDAPAUthenticator::getLDAPtls()) {
            if (!@ldap_start_tls(self::$ds)) {
                 return sprintf('Start TLS failed: [%d] %s',
                                ldap_errno(self::$ds),
                                ldap_error(self::$ds));
            }
        }

        $bindas = LDAPAuthenticator::getBindAs();
        if (!is_null($bindas['binddn'])) {
            $bind = @ldap_bind(self::$ds, $bindas['binddn'],
                               $bindas['password']);
        } else {
            $bind = @ldap_bind(self::$ds);
        }

        // Reset the SilverStripe error handler
        Debug::loadErrorHandlers();
        
        if (!$bind) {
            return 'Could not bind to LDAP server.';
        }

        return true;
    }

    /**
     * Find the user dn based on the given attribute
     *
     * @param string $ldapattribute attribute value to search for. The current
     *               object holds the attrribute name.
     *
     * @return string  The users full DN or boolean on fail
     */
    public function findDN($ldapattribute) {
        /* Search for the user's full DN. */
        $searchfor = LDAPAuthenticator::getSearchFor();
        $search = @ldap_search(self::$ds, LDAPAuthenticator::getBaseDN(),
                               $searchfor['attribute'] . '=' . 
                                      $ldapattribute,
                               array($searchfor['attribute']));
        if (!$search) {
            return false;
        }

        $result = @ldap_get_entries(self::$ds, $search);
        if (is_array($result) && (count($result) > 1)) {
            $dn = $result[0]['dn'];
        } else {
            return false;
        }

        return $dn;
    }


    /**
     * Checks for shadowLastChange and shadowMin/Max support and returns their
     * values.  We will also check for pwdLastSet if Active Directory is
     * support is requested.  For this check to succeed we need to be bound
     * to the directory
     *
     * @param string $dn     The dn of the user
     *
     * @return array  array with keys being "shadowlastchange", "shadowmin"
     *                "shadowmax", "shadowwarning" and containing their
     *                respective values or false for no support.
     */
    private function lookupShadow($dn) {
        /* Init the return array. */
        $lookupshadow = array('shadowlastchange' => false,
                              'shadowmin' => false,
                              'shadowmax' => false,
                              'shadowwarning' => false);

        $result = @ldap_read(self::$ds, $dn, 'objectClass=*');
        if ($result) {
            $information = @ldap_get_entries(self::$ds, $result);

            if (isset($information[0]['shadowmax'][0])) {
                $lookupshadow['shadowmax'] = $information[0]['shadowmax'][0];
            }

            if (isset($information[0]['shadowmin'][0])) {
                $lookupshadow['shadowmin'] = $information[0]['shadowmin'][0];
            }

            if (isset($information[0]['shadowlastchange'][0])) {
                $lookupshadow['shadowlastchange'] = $information[0]['shadowlastchange'][0];
            }

            if (isset($information[0]['shadowwarning'][0])) {
                $lookupshadow['shadowwarning'] = $information[0]['shadowwarning'][0];
            }
        }

        return $lookupshadow;
    }
    
    
    /**
     * Tries to logon to the LDAP server with given dn and password
     * The authentication sets some properties of the object
     * success, wether the logon was a success and message indicating a return
     * message from the authentication.
     *
     * @access public
     *
     * @param string $dn           The dn of the user
     * @param string $ldappassword The password of the user
     *
     * @return boolean  True if the authentication was a success, false 
     *                  otherwise
     */
    public function LDAPAuthenticate($dn, $ldappasswd) {
        // A password should have some lenght. An empty password will result
        // in a succesfull anonymous bind. A password should not be all spaces 
		  if (strlen(trim($ldappasswd)) == 0) {
            self::$message = 'Please enter a password';
            return false;
		  }

        // Restore the default error handler. We dont want a red bordered 
        // screen on error, but a civilized message to the user
		  restore_error_handler();
		  
        $bind = @ldap_bind(self::$ds, $dn, $ldappasswd);
        if ($bind != false) {
            if (LDAPAuthenticator::getPasswdExpiration()) {
                $shadow = self::lookupShadow($dn);

                // Reset the SilverStripe error handler
                Debug::loadErrorHandlers();

                // Do some calculations on the attributes to convert them
                // to the interval [now]-[axpires at]                
                if (isset($shadow['shadowmax']) && isset($shadow['shadowlastchange']) &&
                    isset($shadow['shadowwarning'])) {

                    $today = floor(time() / 86400);
                    $warnday = $shadow['shadowlastchange'] +
                               $shadow['shadowmax'] - $shadow['shadowwarning'];

                    $toexpire = $shadow['shadowlastchange'] +
                                $shadow['shadowmax'] - $today;


                    // Lets be civilized and warn the user that he should 
                    // change his password soon
                    if ($today >= $warnday) {
                        self::$success = true;
		                  self::$message = 'Your password expires in ' . $toexpire . ' days';
		                  return true;
                    }

                    // Out of luck. His password has expired.                    
                    if ($toexpire < 0) {           
                        self::$message = 'Your password has expired';
                        return false;
                    }
                    
                    self::$success = true;
                    return true;
                }
            } else {
                self::$success = true;

                // Reset the SilverStripe error handler
                Debug::loadErrorHandlers();
                return true;
            }
        } else {
            // Reset the SilverStripe error handler
            Debug::loadErrorHandlers();

            self::$message = 'Authentication with your LDAP credentials failed';
            return false;
        }
    }
    
    /**
     * Closes the LDAP connection
     */
    public function close() {
        @ldap_close(self::$ds);
    }
}



/**
 * LDAP authenticator
 */
class LDAPAuthenticator extends Authenticator {

   /**
    * Hostname of the LDAP server
    * you can specify it like a normal hostname or IP number, or 
    * like ldap://hostname or ldaps://hostname. The latter will do
    * encrypted LDAP
    * Note that if you use encryption, you _must_ use the FQDN
    **/
    protected static $ldapserver = "ldap://localhost";
    
    /**
     * LDAP server port, normally 389 for normal LDAP or 636 for LDAPS 
     **/
    protected static $ldapport = 389;
    
   /**
    * You can use TLS for encryption, make sure the LDAP server is
    * specified as ldap://..... and the port is 389 (or _not_ the 
    * ldaps port
    **/
   protected static $tls = false;
    
   /**
    * The DN where your users reside. Be as specific as possible
    * to prevent unexpected guests in the CMS, so typically your
    * directory's base dn (o=.... or dc=....,dc=....) augmented with
    * the ou where the accounts are
    **/
   protected static $basedn = "dc=silverstripe,dc=com";
    
   /**
    * LDAP protocol version to use
    * If yor have set tls to yes, the version must be 3
    **/ 
   protected static $ldapversion = "3";
    
   /**
    * You can use any unique attribute to authenticate as, this 
    * mail, or uid, or any other unique attribute. The description
    * you use here will be put on the login form
    **/
   protected static $searchfor = array(
                                       "attribute" => "uid",
                                       "description" => "User ID"
                                      );

   /**                                   
    * If your LDAP has POSIX style user accounts with shadow support
    * (your LDAP is probably also used to authenticate users on UNIX
    * boxes, you can set expiration to yes. That way, when a user 
    * account expires, ha can also not login to silverstripe
    **/
   protected static $passwordexpiration = true;
              
   /**
    * If your directory doesn't support anonymous searches you can
    * specify an account below that will be used to search for the
    * attribute containing the user ID
    **/
   protected static $bindas = array(
                                    "binddn"   => null,
                                    "password" => null
                                   );
   /**
	 * Set the LDAP Server
	 *
	 * @param string $ldapserver Server identifier
	 */                               
   public static function setLDAPServer($ldapserver) {
       self::$ldapserver = $ldapserver;
   }
   
   /**
	 * Get the LDAP Server
	 *
	 * @return string Server identifier
	 */              
   public static function getLDAPServer() {
       return self::$ldapserver;
   }
   
   /**
	 * Set the LDAP Port
	 *
	 * @param int $ldapport Server identifier
	 */                               
   public static function setLDAPPort($ldapport) {
       self::$ldapport = $ldapport;
   }
   
   /**
	 * Get the LDAP Port
	 *
	 * @return int LDAP tcp port number
	 */              
   public static function getLDAPPort() {
       return self::$ldapport;
   }
   
   /**
	 * Enable tls
	 *
	 * @param bool $tls TLS enabled or not
	 */                               
   public static function setLDAPtls($tls) {
       self::$tls = (bool)$tls;
   }
   
   /**
	 * Get tls status
	 *
	 * @return bool tls on or off
	 */              
   public static function getLDAPtls() {
       return self::$tls;
   }
   
   /**
	 * Set the base DN
	 *
	 * @param string $basedn base DN in LDIF format
	 */                               
   public static function setBaseDN($basedn) {
       self::$basedn = $basedn;
   }
   
   /**
	 * Get the base DN
	 *
	 * @return string Base DN in LDIF format
	 */              
   public static function getBaseDN() {
       return self::$basedn;
   }  
   
   /**
	 * Set LDAP protocol version to be used
	 *
	 * @param int $version Protocol version
	 */                               
   public static function setLDAPVersion($ldapversion) {
       self::$ldapversion = $ldapversion;
   }   
   
   /**
	 * Get LDAP protocol version used
	 *
	 * @return int LDAP version
	 */              
   public static function getLDAPVersion() {
       return self::$ldapversion;
   }

   /**
	 * Set the attribute to look for and description
	 *
	 * @param string $attribute LDAP attribute
	 * @param string $description Description of the LDAP attribute
	 */                               
   public static function setSearchFor($attribute, $description) {
       self::$searchfor['attribute']   = $attribute;
       self::$searchfor['description'] = $description;
   }
   
   /**
	 * Get the attribute and description to look for
	 *
	 * @return array Returns an array of strings with attribute
	 *               name and description
	 */              
   public static function getSearchFor() {
       return self::$searchfor;
   }    
   
   /**
	 * Set password expiration
	 *
	 * @param bool $passwordexpiration Expiration enabled or not
	 */                               
   public static function setPasswdExpiration($passwordexpiration) {
       self::$passwordexpiration = (bool)$passwordexpiration;
   }
   
   /**
	 * Get password expiration status
	 *
	 * @return bool Expiration on or off
	 */              
   public static function getPasswdExpiration() {
       return self::$passwordexpiration;
   }  
   
   /**
	 * Define the LDAP account to use for LDAP searches
	 *
	 * @param string $binddn LDAP account in LDIF format
	 * @param string $password Password
	 */                               
   public static function setBindAs($binddn, $password) {
       self::$bindas['binddn']   = $binddn;
       self::$bindas['password'] = $password;
   }
   
   /**
	 * Get the account to search the directory with
	 *
	 * @return array Returns an array of strings with binddn and password
	 *               name and description
	 */              
   public static function getBindAs() {
       return self::$bindas;
   }      
   
  	/**
	 * Callback function that is called when the authenticator is registered
	 *
	 * Use this method for initialization of a newly registered authenticator.
	 * Just overload this method and it will be called when the authenticator
	 * is registered.
	 * <b>If the method returns FALSE, the authenticator won't be
	 * registered!</b>
	 *
	 * @return bool Returns TRUE on success, FALSE otherwise.
	 */
	protected static function on_register() {
		Member::add_role('LDAPAuthenticatedRole');
		Object::add_extension('Member_Validator', 'LDAPAuthenticatedRole_Validator');
		return parent::on_register();
	}

    
	/**
	 * Method to authenticate an user
	 *
	 * @param array $RAW_data Raw data to authenticate the user
	 * @param Form $form Optional: If passed, better error messages can be
	 *                             produced by using
	 *                             {@link Form::sessionMessage()}
	 * @return bool Returns FALSE if authentication fails, otherwise the
    *              member object    
	 */
	public static function authenticate(array $RAW_data, Form $form = null) {
		$ldapattribute = trim($RAW_data['LDAPAttribute']);
		$ldappasswd    = $RAW_data['LDAPPassword'];

      $ldapaccount = new LDAPPosixAccount;
            
      // LDAP attribute should not be empty
      // LDAP password should not be empty as well, but we check this in the
      // LDAP method itself. This is less error prone if someone else decides
      // to use that class
		if (strlen($ldapattribute) == 0) {
		    if (!is_null($form)) {
		        $form->sessionMessage('Please enter a ' . self::$searchfor['description'], 'bad');
		    }
		    return false;
		} 
		
		$result = $ldapaccount->connect();
      if (is_string($result)) {
      	 if(!is_null($form)) {
              $form->sessionMessage($result, 'bad');
          }
          return false;
      }
      
      $dn = $ldapaccount->findDN($ldapattribute);
      if (is_bool($dn)) {
      	 if (!is_null($form)) {
              $form->sessionMessage('Authentication with your LDAP credentials failed','bad');
          }
          return false;
      }

      // The user exists. Does he also exist within Silverstripe?
      $SQL_identity = Convert::raw2sql($ldapattribute);
		if (!($member = DataObject::get_one("Member","Member.LDAPAttribute = '$SQL_identity'"))) {
			 if(!is_null($form)) {
		        $form->sessionMessage('Your account has not been enabled for LDAP authentication','bad');
		    }
		    return false;
		}

      if ($ldapaccount->LDAPAuthenticate($dn,$ldappasswd)) {
          $ldapaccount->close();
          Session::clear("BackURL");
          
          // Set the security message here. Else it will be shown on logout
          Session::set("Security.Message.message", $ldapaccount->getLDAPAuthMessage());
			 Session::set("Security.Message.type", "good");
          return $member;
      } else {
          $ldapaccount->close();
          if(!is_null($form)) {   
              $form->sessionMessage($ldapaccount->getLDAPAuthMessage(),'bad');
          }
          return false;
      }
	}


	/**
	 * Method that creates the login form for this authentication method
	 *
	 * @param Controller The parent controller, necessary to create the
	 *                   appropriate form action tag
	 * @return Form Returns the login form to use with this authentication
	 *              method
	 */
	public static function get_login_form(Controller $controller) {
		return Object::create("LDAPLoginForm", $controller, "LoginForm");
	}


	/**
	 * Get the name of the authentication method
	 *
	 * @return string Returns the name of the authentication method.
	 */
	public static function get_name() {
		return "LDAP Account";
	}
}

