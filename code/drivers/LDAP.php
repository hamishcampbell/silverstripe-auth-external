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
     * @return boolean on success, error message on fail.
     */
    private function Connect() {
        // First we verify the setting and adapt where needed
        $uri = ExternalAuthenticator::getAuthServer();
        $enc = ExternalAuthenticator::getAuthEnc();
        if (is_null($enc)) {
            $uri = self::$uri_header["default"] . $uri;
        } else {
            $uri = self::$uri_header["$enc"] . $uri;
        }
        
        $port = ExternalAuthenticator::getAuthPort();
        if (is_null($port)) {
            if (is_null($enc)) {
                $port = self::$portlist["default"];
            } else {
                $port = self::$portlist["$enc"];
            }
        }

        $version = ExternalAuthenticator::getOption("ldapversion");
        if (is_null($version))
        {
            $version = self::$version;
        }        

        $bindas  = ExternalAuthenticator::getOption("bind_as");
        $bindpw  = ExternalAuthenticator::getOption("bind_pw");            
    
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
     * @param string $ldapattribute attribute value to search for. The current
     *               object holds the attrribute name.
     *
     * @return string  The users full DN or boolean on fail
     */
    private function findDN($ldapattribute) {
        /* Check if basedn and attribute are set */
        $searchfor = ExternalAuthenticator::getOption("attribute");
        $basedn    = ExternalAuthenticator::getOption("basedn");
        if (is_null($searchfor) || is_null($basedn)) {
            return false;
        }
        
        /* Search for the user's full DN. */
        $search = @ldap_search(self::$ds, $basedn, 
                               $searchfor . '=' . $ldapattribute,
                               array($searchfor));
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
     * Tries to logon to the LDAP server with given id and password
     *
     * @access public
     *
     * @param string $external_uid    The ID entered
     * @param string $external_passwd The password of the user
     *
     * @return boolean  True if the authentication was a success, false 
     *                  otherwise
     */
    public function Authenticate($external_uid, $external_passwd) {
        // A password should have some lenght. An empty password will result
        // in a succesfull anonymous bind. A password should not be all spaces 
		  if (strlen(trim($external_passwd)) == 0) {
            ExternalAuthenticator::setAuthMessage(_t('LDAP_Authenticator.NoPasswd','Please enter a password'));
            return false;
		  }

        // Do we support password expiration?
        $expire = ExternalAuthenticator::getOption("passwd_expiration");
        
		  $result = self::Connect();
        if (is_string($result)) {
            ExternalAuthenticator::setAuthMessage($result);
            return false;
        }
      
        $dn = self::findDN($external_uid);
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
            if (!is_null($expire) && $expire) {
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

                    // Out of luck. His password has expired.                    
                    if ($toexpire < 0) {           
                        ExternalAuthenticator::setAuthMessage(_t('LDAP_Authenticator.Expired','Your password has expired'));
                    } else {
                        $success = true;

                        // Lets be civilized and warn the user that he should 
                        // change his password soon
                        if ($today >= $warnday) {
		                      ExternalAuthenticator::setAuthMessage(sprintf(_t('LDAP_Authenticator.WillExpire',
		                          'Your password expires in %d days'), $toexpire));                    
                        }
                    }
                } else {
                    $success = true;
                }
            } else {
                // Reset the SilverStripe error handler
                Debug::loadErrorHandlers();
                $success = true;
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


