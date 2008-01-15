<?php
/**
 * LDAP driver for the external authentication driver
 * This driver supports the SSL/TLS setting and the following options
 * A * means you _must_ set this option
 * *basedn     --> DN of the subtree to be searched for the user account
 * *attribute  --> We will look for this attribute in the basedn
 * ldapversion --> Connect using this version of the protocol
 * passwd_expiration --> POSIX Shadow expiration mechanism is supported
 * bind_as     --> The DN used for LDAP binding if the LDAP does not support
 *                 anonymous searches
 * bind_pw     --> Password for the previous DN
 *
 * @author Roel Gloudemans <roel@gloudemans.info> 
 */

class LDAP_Authenticator {

    /**
     * LDAP connection handle
     **/
    protected static $ds;

    /**
     * The default LDAP portlist in case it is not defined
     */   
    protected static $portlist   = array('tls'     => 389,
                                         'ssl'     => 636,
                                         'default' => 389);
                                       
    /**
     * In this driver we specify the LDAP driver by URI
     */
    protected static $uri_header = array ('tls'     => "ldap://",
                                          'ssl'     => "ldaps://",
                                          'default' => "ldap://");
                                          
    /**
     * Default version of the LDAP protocol to use
     */    
    protected static $version = 3;   


    /**
     * Does an ldap connect and binds as the guest user or as the optional dn.
     *
     * @param  string $source Authentication source to be used 
     * @return boolean on success, error message on fail.
     */
    private function Connect($source) {
        // First we verify the setting and adapt where needed
        $uri = ExternalAuthenticator::getAuthServer($source);
        $enc = ExternalAuthenticator::getAuthEnc($source);
        if (is_null($enc)) {
            $uri = self::$uri_header["default"] . $uri;
        } else {
            $uri = self::$uri_header["$enc"] . $uri;
        }
        
        $port = ExternalAuthenticator::getAuthPort($source);
        if (is_null($port)) {
            if (is_null($enc)) {
                $port = self::$portlist["default"];
            } else {
                $port = self::$portlist["$enc"];
            }
        }

        $version = ExternalAuthenticator::getOption($source, "ldapversion");
        if (is_null($version))
        {
            $version = self::$version;
        }        

        $bindas  = ExternalAuthenticator::getOption($source, "bind_as");
        $bindpw  = ExternalAuthenticator::getOption($source, "bind_pw");            
    
        // Revert to the PHP error handler to prevent the SilverStripe
        // error handler from interfering
        restore_error_handler();

        /* Connect to the LDAP server. */
        self::$ds = @ldap_connect($uri, $port);
        if (!self::$ds) {
            Debug::loadErrorHandlers();
            return _t('LDAP_Authenticator.NotConnected','Failed to connect to LDAP server.');
        }

        if (!ldap_set_option(self::$ds, LDAP_OPT_PROTOCOL_VERSION, $version)) {
             Debug::loadErrorHandlers();
             return sprintf(_t('LDAP_Authenticator.Version','Set LDAP protocol version to %d failed'), $version);
        }
        
        if ($enc == "tls") {
            if (!@ldap_start_tls(self::$ds)) {
                 return sprintf(_t('LDAP_Authenticator.TLS','Start TLS failed: [%d] %s'),
                                ldap_errno(self::$ds),
                                ldap_error(self::$ds));
            }
        }

        if (!is_null($bindas)) {
            $bind = @ldap_bind(self::$ds, $bindas, $bindpw);
        } else {
            $bind = @ldap_bind(self::$ds);
        }

        // Reset the SilverStripe error handler
        Debug::loadErrorHandlers();
        
        if (!$bind) {
            return _t('LDAP_Authenticator.NoBind','Could not bind to LDAP server.');
        }

        return true;
    }


    /**
     * Find the user dn based on the given attribute
     *
     * @param  string $source Authentication source to be used 
     * @param  string $ldapattribute attribute value to search for. The current
     *                object holds the attrribute name.
     * @return string  The users full DN or boolean on fail
     */
    private function findDN($source, $ldapattribute) {
        /* Check if basedn and attribute are set */
        $searchfor = ExternalAuthenticator::getOption($source, "attribute");
        $basedn    = ExternalAuthenticator::getOption($source, "basedn");
        if (is_null($searchfor) || is_null($basedn)) {
            return false;
        }
        
        /* Now create the search filter */
        $attribute_array = ExternalAuthenticator::getOption($source,"extra_attributes");
        if (!is_null($attribute_array) && is_array($attribute_array)) {
            $filter =  "(& ";
            $filter .= "(".$searchfor."=".$ldapattribute.")";
            foreach ($attribute_array as $attribute => $value) {
                $filter .= "(".$attribute."=".$value.")";
            }
            $filter .= ")";
        } else {
            $filter = "(".$searchfor."=".$ldapattribute.")";
        }
        
        if (is_array($basedn)) {
          foreach ($basedn as $dn) {
            /* Search for the user's full DN. */
            $search = @ldap_search(self::$ds, $dn,
                                   $filter,
                                   array($searchfor));
            
            if ($search) {
              # Check for count. Some LDAPs return a result with count 0
              # when search has failed
              $result =  @ldap_get_entries(self::$ds, $search);
              if ($result["count"] > 0 ) {
                break;
              }
            }
          }
        } else {
          /* Search for the user's full DN. */
          $search = @ldap_search(self::$ds, $basedn, 
                                 $filter,
                                 array($searchfor));
          if ($search) {
            $result =  @ldap_get_entries(self::$ds, $search);
          }
        }

        if ((!$search) || ($result["count"] == 0)) {
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
     * Gets additional user record details such as name and expirery
     * settings
     * For this lookup to succeed we need to be bound
     * to the directory
     *
     * @param  string $source Authentication source to be used      
     * @param  string $dn     The dn of the user
     *
     * @return array  array with keys being "shadowlastchange", "shadowmin"
     *                "shadowmax", "shadowwarning", "firstname", "surname",
     *                and "email" and containing their
     *                respective values.
     */
    private function lookupDetails($source, $dn) {
        /* Init the return array. */
        $lookupdetails = array('shadowlastchange' => false,
                               'shadowmin'        => false,
                               'shadowmax'        => false,
                               'shadowwarning'    => false,
                               'firstname'        => 'unknown',
                               'surname'          => 'unknown',
                               'email'            => 'root@localhost');

        $result = @ldap_read(self::$ds, $dn, 'objectClass=*');
        if ($result) {
            $information = @ldap_get_entries(self::$ds, $result);

            if (isset($information[0]['shadowmax'][0])) {
                $lookupdetails['shadowmax'] = $information[0]['shadowmax'][0];
            } 

            if (isset($information[0]['shadowmin'][0])) {
                $lookupdetails['shadowmin'] = $information[0]['shadowmin'][0];
            }

            if (isset($information[0]['shadowlastchange'][0])) {
                $lookupdetails['shadowlastchange'] = $information[0]['shadowlastchange'][0];
            }

            if (isset($information[0]['shadowwarning'][0])) {
                $lookupdetails['shadowwarning'] = $information[0]['shadowwarning'][0];
            }

            $firstname_attr = strtolower(ExternalAuthenticator::getOption($source, "firstname_attr"));
            if (!is_null($firstname_attr)) {
                if (isset($information[0][$firstname_attr][0])) {
                    $lookupdetails['firstname'] = $information[0][$firstname_attr][0];
                }
            }

            $surname_attr = strtolower(ExternalAuthenticator::getOption($source, "surname_attr"));
            if (!is_null($surname_attr)) {
                if (isset($information[0][$surname_attr][0])) {
                    $lookupdetails['surname'] = $information[0][$surname_attr][0];
                }
            }

            $email_attr = strtolower(ExternalAuthenticator::getOption($source, "email_attr"));
            if (!is_null($email_attr)) {
                if (isset($information[0][$email_attr][0])) {
                    $lookupdetails['email'] = $information[0][$email_attr][0];
                }
            }
        }

        return $lookupdetails;
    }


    /**
     * Tries to logon to the LDAP server with given id and password
     *
     * @access public
     *
     * @param string $source          The Authentication source to be used
     * @param string $external_uid    The ID entered
     * @param string $external_passwd The password of the user
     *
     * @return mixed    Account details if succesful , false if not 
     */
    public function Authenticate($source, $external_uid, $external_passwd) {
        // A password should have some lenght. An empty password will result
        // in a succesfull anonymous bind. A password should not be all spaces 
        if (strlen(trim($external_passwd)) == 0) {
            ExternalAuthenticator::setAuthMessage(_t('LDAP_Authenticator.NoPasswd','Please enter a password'));
            return false;
        }

        // Do we support password expiration?
        $expire = ExternalAuthenticator::getOption($source, "passwd_expiration");
        
        $result = self::Connect($source);
        if (is_string($result)) {
            ExternalAuthenticator::setAuthMessage($result);
            return false;
        }
      
        $dn = self::findDN($source, $external_uid);
        if (is_bool($dn)) {
            @ldap_close(self::$ds);
            ExternalAuthenticator::setAuthMessage(_t('ExternalAuthenticator.Failed'));
            return false;
        }

        // Restore the default error handler. We dont want a red bordered 
        // screen on error, but a civilized message to the user
        restore_error_handler();
		  
        $success = false;    //Initialize the result of the authentication        
        $bind = @ldap_bind(self::$ds, $dn, $external_passwd);
        if ($bind != false) {
            $accountdetails = self::lookupDetails($source, $dn);

            if (!is_null($expire) && $expire) {
                // Reset the SilverStripe error handler
                Debug::loadErrorHandlers();

                // Do some calculations on the attributes to convert them
                // to the interval [now]-[axpires at]                
                if ($accountdetails['shadowmax'] && $accountdetails['shadowlastchange'] &&
                    $accountdetails['shadowwarning']) {

                    $today = floor(time() / 86400);
                    $warnday = $accountdetails['shadowlastchange'] +
                               $accountdetails['shadowmax'] - $accountdetails['shadowwarning'];

                    $toexpire = $accountdetails['shadowlastchange'] +
                                $accountdetails['shadowmax'] - $today;

                    // Out of luck. His password has expired.                    
                    if ($toexpire < 0) {           
                        ExternalAuthenticator::setAuthMessage(_t('LDAP_Authenticator.Expired','Your password has expired'));
                    } else {
                        $success = $accountdetails;

                        // Lets be civilized and warn the user that he should 
                        // change his password soon
                        if ($today >= $warnday) {
		                      ExternalAuthenticator::setAuthMessage(sprintf(_t('LDAP_Authenticator.WillExpire',
		                          'Your password expires in %d days'), $toexpire));                    
                        }
                    }
                } else {
                    $success = $accountdetails;
                }
            } else {
                // Reset the SilverStripe error handler
                Debug::loadErrorHandlers();
                $success = $accountdetails;
            }
        } else {
            // Reset the SilverStripe error handler
            Debug::loadErrorHandlers();

            ExternalAuthenticator::setAuthMessage(_t('ExternalAuthenticator.Failed'));
            $success =  false;
        }
        
        @ldap_close(self::$ds);
        return $success;
    }
    
}
