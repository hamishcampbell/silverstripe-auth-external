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
     * @param string $external_uid    The ID entered by the user (for logging purposes only)
     * @return boolean on success, error message on fail.
     */
    private function Connect($source, $external_uid) {
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

        ExternalAuthenticator::AuthLog($external_uid.'.ldap - Connecting to ' . $uri . ' port ' . 
                                       $port . ' LDAP version ' . $version);
        ExternalAuthenticator::AuthLog($external_uid.'.ldap - If process stops here, check PHP LDAP module'); 
        
        $bindas  = ExternalAuthenticator::getOption($source, "bind_as");
        $bindpw  = ExternalAuthenticator::getOption($source, "bind_pw");            
    
        // Revert to the PHP error handler to prevent the SilverStripe
        // error handler from interfering
        restore_error_handler();

        /* Connect to the LDAP server. */
        self::$ds = @ldap_connect($uri, $port);
        if (!self::$ds) {
            Debug::loadErrorHandlers();
            ExternalAuthenticator::AuthLog($external_uid.'.ldap - Failed to connect');
            return _t('LDAP_Authenticator.NotConnected','Failed to connect to LDAP server.');
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.ldap - Connect succeeded');
        }
        
        if (!ldap_set_option(self::$ds, LDAP_OPT_PROTOCOL_VERSION, $version)) {
             Debug::loadErrorHandlers();
             ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP set to prot. version ' . $version . ' failed');
             return sprintf(_t('LDAP_Authenticator.Version','Set LDAP protocol version to %d failed'), $version);
        } else {
             ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP set to protocol version ' . $version);
        }
        
        if ($enc == "tls") {
            if (!@ldap_start_tls(self::$ds)) {
                 ExternalAuthenticator::AuthLog($external_uid.'.ldap - TLS initialization failed ' . 
                                                ldap_errno(self::$ds) . ':' . ldap_error(self::$ds));
                 return sprintf(_t('LDAP_Authenticator.TLS','Start TLS failed: [%d] %s'),
                                ldap_errno(self::$ds),
                                ldap_error(self::$ds));
            } else {
                 ExternalAuthenticator::AuthLog($external_uid.'.ldap - TLS initialization success');
            } 
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.ldap - TLS not set');
        }

        if (!is_null($bindas)) {
            $bind = @ldap_bind(self::$ds, $bindas, $bindpw);
        } else {
            $bind = @ldap_bind(self::$ds);
        }

        // Reset the SilverStripe error handler
        Debug::loadErrorHandlers();
        
        if (!$bind) {
            ExternalAuthenticator::AuthLog($external_uid.'.ldap - Bind failed ' . 
                                           ldap_errno(self::$ds) . ':' . ldap_error(self::$ds));
            return _t('LDAP_Authenticator.NoBind','Could not bind to LDAP server.');
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.ldap - Bind success');
        }
        
        return true;
    }


    /**
     * Find the user dn based on the given attribute
     *
     * @param  string $source Authentication source to be used 
     * @param  string $ldapattribute attribute value to search for. The current
     *                object holds the attribute name.
     * @return string  The users full DN or boolean on fail
     */
    private function findDN($source, $ldapattribute) {
        /* Check if basedn and attribute are set */
        $searchfor = ExternalAuthenticator::getOption($source, 'attribute');
        $basedn    = ExternalAuthenticator::getOption($source, 'basedn');
        if (is_null($searchfor) || is_null($basedn)) {
            ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - BaseDN and/or search attribute not set'); 
            return false;
        }
        
        /* Now create the search filter */
        $attribute_array = ExternalAuthenticator::getOption($source,'extra_attributes');
        if (!is_null($attribute_array) && is_array($attribute_array)) {
            $filter =  '(& ';
            $filter .= '('.$searchfor.'='.$ldapattribute.')';
            foreach ($attribute_array as $attribute => $value) {
                $filter .= '('.$attribute.'='.$value.')';
            }
            $filter .= ')';
        } else {
            $filter = '('.$searchfor.'='.$ldapattribute.')';
        }
        ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - LDAP filter set to ' . $filter); 
        
        if (is_array($basedn)) {
            foreach ($basedn as $dn) {
                ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - Searching in tree ' . $dn); 
                /* Search for the user's full DN. */
                $search = @ldap_search(self::$ds, $dn,
                                       $filter,
                                       array($searchfor));
              
                if ($search) {
                    ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - Search succeeded'); 
              
                    # Check for count. Some LDAPs return a result with count 0
                    # when search has failed
                    $result =  @ldap_get_entries(self::$ds, $search);
                    if ($result['count'] > 0 ) {
                        ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - Found ' . $result['count'] . ' results'); 
                        break;
                    } else {
                        ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - No matching results');
                    } 
                } else {
                    ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - Search failed');
                }  
            }
        } else {
            /* Search for the user's full DN. */
            ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - Searching in tree ' . $basedn);
            $search = @ldap_search(self::$ds, $basedn, 
                                   $filter,
                                   array($searchfor));
            if ($search) {
                ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - Search succeeded');
                $result =  @ldap_get_entries(self::$ds, $search);
                ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - Found ' . $result['count'] . ' results');
            } else {
                ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - Search failed');
            }
        }

        if ((!$search) || ($result['count'] == 0) || (!is_array($result))) {
            ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - No matches found');
            return false;
        }

        $dn = $result[0]['dn'];
        ExternalAuthenticator::AuthLog($ldapattribute.'.ldap - DN ' . $dn . ' matches criteria');
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
     * @param string $external_uid    The ID entered by the user (for logging purposes only)
     *
     * @return array  array with keys being "shadowlastchange", "shadowmin"
     *                "shadowmax", "shadowwarning", "firstname", "surname",
     *                and "email" and containing their
     *                respective values.
     */
    private function lookupDetails($source, $dn, $external_uid) {
        /* Init the return array. */
        $lookupdetails = array('shadowlastchange' => array('value' => false, 'attr' => 'shadowlastchange'),
                               'shadowmin'        => array('value' => false, 'attr' => 'shadowmin'),
                               'shadowmax'        => array('value' => false, 'attr' => 'shadowmax'),
                               'shadowwarning'    => array('value' => false, 'attr' => 'shadowwarning'),
                               'firstname'        => array('value' => 'unknown', 
                                                           'attr'  => strtolower(ExternalAuthenticator::getOption($source, 'firstname_attr'))
                                                          ),
                               'surname'          => array('value' =>'unknown',
                                                           'attr'  => strtolower(ExternalAuthenticator::getOption($source, 'surname_attr'))
                                                          ),
                               'email'            => array('value' => 'root@localhost',
                                                           'attr'  => strtolower(ExternalAuthenticator::getOption($source, 'email_attr'))
                                                          )
                              );

        ExternalAuthenticator::AuthLog($external_uid.'.ldap - Reading details of DN ' . $dn);
        $result = @ldap_read(self::$ds, $dn, 'objectClass=*');
        if ($result) {
            ExternalAuthenticator::AuthLog($external_uid.'.ldap - Lookup of details succeeded');
            $information = @ldap_get_entries(self::$ds, $result);

            foreach ($lookupdetails as $key => $lookupdetail) {
                if (!is_null($lookupdetail['attr'])) {
                    ExternalAuthenticator::AuthLog($external_uid.'.ldap - Looking up ' . $lookupdetail['attr']);
                    if (isset($information[0][$lookupdetail['attr']][0])) {
                        $lookupdetails[$key]['value'] = $information[0][$lookupdetail['attr']][0];
                        ExternalAuthenticator::AuthLog($external_uid.'.ldap - ' . $lookupdetail['attr'] . ' set to ' . 
                                                       $lookupdetails[$key]['value']); 
                    } else {
                        ExternalAuthenticator::AuthLog($external_uid.'.ldap - Attribute ' . 
                                                       $lookupdetail['attr'] . ' not set');
                    } 
                } else {
                    ExternalAuthenticator::AuthLog($external_uid.'.ldap - Dont know how to find ' . $key);
                }
            }                              
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.ldap - Lookup of details failed');
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
        $expire = ExternalAuthenticator::getOption($source, 'passwd_expiration');
        
        $result = self::Connect($source, $external_uid);
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
        
        ExternalAuthenticator::AuthLog($external_uid.'.ldap - Binding to LDAP as ' . $dn);        
        $bind = @ldap_bind(self::$ds, $dn, $external_passwd);
        if ($bind != false) {
            ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP accepted password for ' . $dn);        
            $accountdetails = self::lookupDetails($source, $dn, $external_uid);

            if (!is_null($expire) && $expire) {
                ExternalAuthenticator::AuthLog($external_uid.'.ldap - Check if password has expired');        
                // Reset the SilverStripe error handler
                Debug::loadErrorHandlers();

                // Do some calculations on the attributes to convert them
                // to the interval [now]-[expires at]                
                if ($accountdetails['shadowmax']['value'] && $accountdetails['shadowlastchange']['value'] &&
                    $accountdetails['shadowwarning']['value']) {

                    $today = floor(time() / 86400);
                    $warnday = $accountdetails['shadowlastchange']['value'] +
                               $accountdetails['shadowmax']['value'] - $accountdetails['shadowwarning']['value'];

                    $toexpire = $accountdetails['shadowlastchange']['value'] +
                                $accountdetails['shadowmax']['value'] - $today;
                                
                    ExternalAuthenticator::AuthLog($external_uid.'.ldap - ' . $toexpire . ' before password expires ' .
                                                   $towarn . ' days before warning');                

                    // Out of luck. His password has expired.                    
                    if ($toexpire < 0) {           
                        ExternalAuthenticator::setAuthMessage(_t('LDAP_Authenticator.Expired','Your password has expired'));
                        ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP Authentication FAILED due to expired password');                
                    } else {
                        ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP Authentication success');                
                    
                        $success = array('firstname' => $accountdetails['firstname']['value'],
                                         'surname'   => $accountdetails['surname']['value'],
                                         'email'     => $accountdetails['email'][value]
                                        );

                        // Lets be civilized and warn the user that he should 
                        // change his password soon
                        if ($today >= $warnday) {
		                      ExternalAuthenticator::setAuthMessage(sprintf(_t('LDAP_Authenticator.WillExpire',
		                          'Your password expires in %d days'), $toexpire));                    
                        }
                    }
                } else {
                    ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP password expiry enabled, but attributes not set; IGNORING');                
                    ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP Authentication success');                
                    $success = array('firstname' => $accountdetails['firstname']['value'],
                                     'surname'   => $accountdetails['surname']['value'],
                                     'email'     => $accountdetails['email'][value]
                                    );
                }
            } else {
                ExternalAuthenticator::AuthLog($external_uid.'.ldap - Password expiry not enabled');        
                // Reset the SilverStripe error handler
                Debug::loadErrorHandlers();
                
                ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP Authentication success');                
                $success = array('firstname' => $accountdetails['firstname']['value'],
                                 'surname'   => $accountdetails['surname']['value'],
                                 'email'     => $accountdetails['email'][value]
                                );
            }
        } else {
            // Reset the SilverStripe error handler
            Debug::loadErrorHandlers();

            ExternalAuthenticator::AuthLog($external_uid.'.ldap - LDAP authentication for ' . $dn . ' failed');        
            ExternalAuthenticator::setAuthMessage(_t('ExternalAuthenticator.Failed'));
            $success =  false;
        }
        
        @ldap_close(self::$ds);
        return $success;
    }
    
}
