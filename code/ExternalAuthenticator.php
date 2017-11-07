<?php

/**
 * LDAP authenticator and controller
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 */

class ExternalAuthenticator extends Authenticator {

   /**
    * Array which contains the authentication details of all authentication
    * sources. The index of the array will function as the unique source ID
    * which will be stored with the user name to allow for the same user ID
    * in multiple sources
    **/
   protected static $authsources = array();

   /**
    * Description of user id
    * This description is used for all sources defined
    **/
   protected static $anchordesc = 'User ID';

   /**
    * Use Anchor for login or the e-mail address
    **/
   protected static $useanchor = false;

   /**
    * Message that results from authenticating
    **/
   protected static $authmessage = '';

   /**
    * Enable logging of the authentication process to a file for debug purposes
    * Set to filename or false to disable
    **/
   protected static $authdebug = false;

   /**
    * Audit log
    * Set to filename or false to disable
    **/
   protected static $auditlogfile = false;

   /**
    * Audit log using a database table
    **/
   protected static $auditlogsstripe = false;

   /**
    * Timestamp for this authentication try
    **/
   protected static $timestamp = null;


   /**
    * Creates an authentication source with default settings
    *
    * @param string $sourceid Source ID
    * @param string $authtype Authentication server type
    * @param string $nicename Nice name for source chooser on login form
    **/
   public static function createSource($sourceid, $authtype, $nicename) {
       self::$authsources["$sourceid"] = array(
           'authtype'      => $authtype,    //Driver
           'nicename'      => $nicename,    //Name to show in source chooser
           'authserver'    => 'localhost',  //IP or DNS name of server
           'authport'      => null,         //IP port to use
           'authsslock'    => true,         //Check SStripes locking mechanism
           'anchordesc'    => 'User ID',    //How do we refer to a user id
           'encryption'    => null,         //Enable SSL or TLS encryption
           'autoadd'       => false,        //Automatically add users?
           'valid_client'  => true,         //Client is within listed netmasks
           'defaultdomain' => null,         //Default mail domain for auto
                                            //adding accounts
                                            //Only works if driver cannot
                                            //get user mail.
           "authoption" => array()          //Driver specific options
       );

       if (is_null(self::$timestamp)) self::$timestamp = date('His');
   }


   /**
    * Get all source ids
    *
    * return array Array of source id's. Filter out any sources that should
    * not be used based on the clients IP
    **/
   public static function getSources() {
       $validsources = array();
       foreach (array_keys(self::$authsources) as $thissource) {
           if (self::getValidClient($thissource)) $validsources[] = $thissource;
       }
       return $validsources;
   }

   /**
    * Get an array with the source ids as key and the nicenames as value
    * handdy for creating forms
    **/
   public static function getIDandNames() {
       $result = array();
       $keys   = array_keys(self::$authsources);

       foreach ($keys as $sourceid) {
           $result[$sourceid] = self::$authsources["$sourceid"]['nicename'];
       }

       return $result;
   }


   /**
    * Get the Authentication Type
    *
    * @param  string $sourceid Source ID
    * @return string Protocol identifier
    **/
   public static function getAuthType($sourceid) {
       return self::$authsources["$sourceid"]['authtype'];
   }


   /**
    * Get the source nice name
    *
    * @param  string $sourceid Source ID
    * @return string Nice name
    **/
   public static function getNiceName($sourceid) {
       return self::$authsources["$sourceid"]['nicename'];
   }

   /**
    * Set the Authentication Server
    *
    * @param string $sourceid   Source ID
    * @param string $authserver Server identifier
    */
   public static function setAuthServer($sourceid, $authserver) {
       self::$authsources["$sourceid"]['authserver'] = $authserver;
   }

   /**
    * Get the Authentication Server
    *
    * @param  string $sourceid Source ID
    * @return string Server identifier
    */
   public static function getAuthServer($sourceid) {
       return self::$authsources["$sourceid"]['authserver'];
   }

   /**
    * Set the authentication port
    *
    * @param string $sourceid Source ID
    * @param string $authport TCP port
    */
   public static function setAuthPort($sourceid, $authport) {
       self::$authsources["$sourceid"]['authport'] = $authport;
   }

   /**
    * Get the authentication Port
    *
    * @param  string $sourceid Source ID
    * @return int authport tcp port number
    */
   public static function getAuthPort($sourceid) {
       return self::$authsources["$sourceid"]['authport'];
   }

   /**
    * Enable tls/ssl
    *
    * @param string $sourceid Source ID
    * @param string $enc      set to ssl or tls
    */
   public static function setAuthEnc($sourceid, $enc) {
       $enc = strtolower($enc);
       if (in_array($enc,array('tls','ssl')))
       {
           self::$authsources["$sourceid"]['encryption'] = $enc;
       }
   }

   /**
    * Get tls status
    *
    * @param  string $sourceid Source ID
    * @return string tls or ssl
    */
   public static function getAuthEnc($sourceid) {
       return self::$authsources["$sourceid"]['encryption'];
   }

   /**
    * Set default mail domain for auto-adding new mail accounts. This setting
    * only works if the driver cannot return a mail address
    *
    * @param string $sourceid Source ID
    * @param string $domain      default domain (like siverstripe.com)
    */
   public static function setDefaultDomain($sourceid, $domain) {
       self::$authsources["$sourceid"]['defaultdomain'] = $domain;
   }

   /**
    * Returns the default domain
    *
    * @param  string $sourceid Source ID
    * @return string domain (like silverstripe.com)
    */
   public static function getDefaultDomain($sourceid) {
       return self::$authsources["$sourceid"]['defaultdomain'];
   }

   /**
    * Set option for the authentication method
    *
    * @param string $sourceid Source ID
    * @param string $key keyname for the option
    * @param string $value value of the key
    */
   public static function setOption($sourceid, $key, $value) {
       self::$authsources[$sourceid]['authoption']["$key"] = $value;
   }

   /**
    * Get authentication option
    *
    * @param  string $sourceid Source ID
    * @param  string $key Keyname for the value to return
    * @return string value of the corresponding key
    */
   public static function getOption($sourceid, $key) {
       if (isset(self::$authsources["$sourceid"]['authoption']["$key"])) {
           return self::$authsources["$sourceid"]['authoption']["$key"];
       } else {
           return null;
       }
   }

   /**
    * Set the current member auto-add status
    *
    * @param string $sourceid Source ID
    * @param mixed  $doadd false to disable or group name to enable
    */
   public static function setAutoAdd($sourceid, $doadd) {
          self::$authsources["$sourceid"]['autoadd'] = $doadd;
   }

   /**
    * Get the current member auto-add status
    *
    * @param  string $sourceid Source ID
    * @return mixed  Auto add (groupname) or not?
    */
   public static function getAutoAdd($sourceid) {
       return self::$authsources["$sourceid"]['autoadd'];
   }

   /**
    * Set the name of the user id
    *
    * @param string $anchordesc Description of user id
    */
   public static function setAnchorDesc($anchordesc) {
       self::$anchordesc = $anchordesc;
   }

   /**
    * Get the user id description
    *
    * @return string anchordesc Description
    */
   public static function getAnchorDesc() {
       return self::$anchordesc;
   }

   /**
    * Select the Anchor or the mail address to logon
    *
    * @param boolean $useanchor True of Anchor usage, false for mail
    **/
   public static function setUseAnchor($useanchor) {
       self::$useanchor = $useanchor;
   }

   /**
    * Select the Anchor or the mail address to logon
    *
    * @return boolean $useanchor True of Anchor usage, false for mail
    **/
   public static function getUseAnchor() {
       return self::$useanchor;
   }

   /**
    * Set the authentication checks to sequential or user chosable
    *
    * @param bool $sequential
    **/
   // DEPRECATED
   // DEPRECATED. Set UseAnchor to false instead
   // DEPRECATED
   public static function setAuthSequential($sequential) {
       self::$useanchor = !$sequential;
   }

   /**
    * Do we let the user choose or do we check sources in sequence
    *
    * @return bool True for sequential checks
    **/
   // DEPRECATED
   // DEPRECATED. Set UseAnchor to false instead
   // DEPRECATED
   public static function getAuthSequential() {
       return !self::$useanchor;
   }

   /**
    * Enable or disable the logging of the authentication process
    *
    * @param mixed $debug  File name or false to disable
    **/
   public static function setAuthDebug($debug) {
       self::$authdebug = $debug;
   }

   /**
    * Do we log the authentication process to a file?
    *
    * @return mixed File name or false for disabled
    **/
   public static function getAuthDebug() {
       return self::$authdebug;
   }

   /**
    * Enable or disable the logging of logon attempts
    *
    * @param mixed $auditlogfile  File name or false for disabled
    **/
   public static function setAuditLogFile($auditlogfile) {
       self::$auditlogfile = $auditlogfile;
   }

   /**
    * Do we log logon attmpts?
    *
    * @return mixed Filename or false for disabled
    **/
   public static function getAuditLogFile() {
       return self::$auditlogfile;
   }

   /**
    * Enable or disable the logging of logon attempts
    *
    * @param bool $auditlogstripe  Enable database logging
    **/
   public static function setAuditLogSStripe($auditlogsstripe) {
       self::$auditlogsstripe = $auditlogsstripe;
   }

   /**
    * Do we log logon attmpts?
    *
    * @return bool Enabled or disabled
    **/
   public static function getAuditLogSStripe() {
       return self::$auditlogsstripe;
   }

   /**
    * Enable or disable the usage of silverstripes login mechanism
    * if the password source has its own mechanism disable this
    * Member::lock_out_after_incorrect_logins should be set to a non-null value
    *
    * @param bool $sslock
    **/
   public static function setAuthSSLock($sourceid,$sslock) {
       self::$authsources["$sourceid"]['authsslock'] = $sslock;
   }

   /**
    * Do we use silverstripes authentication mechanism?
    *
    * @return bool True for password locking
    **/
   public static function getAuthSSLock($sourceid) {
       return self::$authsources["$sourceid"]['authsslock'];
   }

   /**
    * Set a message as a result of authenticating
    * (to be used by the authentication drivers)
    *
    * @param string $message The message to set
    */
   public static function setAuthMessage($message){
       self::$authmessage = $message;
   }

   /**
    * Get the authentication message
    *
    * @return string The message
    */
   public static function getAuthMessage() {
       return self::$authmessage;
   }

   /**
    * Set a valid range of IP numbers for a source
    *
    * @param string $sourceid Source ID
    * @param mixed  $netmasks Array or string of "network/netmask"
    *                         like (192.168.0.0/24 or 192.168.0.0/255.255.255.0)
    */
   public static function setValidAddress($sourceid, $netmasks){
       self::$authsources["$sourceid"]['valid_client'] = false;

       $valid_network = new AuthNetworkAddress();
       if (is_array($netmasks)) {
           foreach ($netmasks as $netmask) {
               if ($valid_network->applyNetmask($netmask)) {
                   self::$authsources["$sourceid"]['valid_client'] = true;
                   self::AuthLog('Client IP ' . $valid_network->getClientIP() .
                                 ' is in ' . $netmask);
               } else {
                   self::AuthLog('Client IP ' . $valid_network->getClientIP() .
                                 ' is NOT in ' . $netmask);
               }
           }
       } else {
          if ($valid_network->applyNetmask($netmasks)) {
              self::$authsources["$sourceid"]['valid_client'] = true;
              self::AuthLog('Client IP ' . $valid_network->getClientIP() .
                            ' is in ' . $netmasks);
          } else {
              self::AuthLog('Client IP ' . $valid_network->getClientIP() .
                            ' is NOT in ' . $netmasks);
          }
       }
   }

   /**
    * Returns if the client is in a valid IP range
    *
    * @param string $sourceid Source ID
    *
    * @return boolean Valid client or not
    */
   public static function getValidClient($sourceid) {
       return self::$authsources["$sourceid"]['valid_client'];
   }


   /**
    * Writes a message to the debug logfile
    **/
   public static function AuthLog($message) {
       if (!is_bool(self::getAuthDebug())) {
           if (!@error_log(date(DATE_RFC822). ' - ' . self::$timestamp . ' - ' .
                           $message . "\n",3,self::getAuthDebug())) {
               self::setAuthMessage(_t('ExternalAuthenticator.LogFailed', 'Logging to debug log failed'));
           }
       }
   }

   /**
    * Writes a message to the audit log
    *
    * @param object  $member       The member if found in the database
    * @param string  $anchor       The login name if the user
    * @param string  $action_type  What was tried?
    * @param string  $because      Reason for success
    * @param boolean $success      Did we succeed
    * @param string  $source_id    For which source
    **/
   public static function AuditLog($member, $anchor, $action_type, $because, $success, $source_id) {
       if (self::getAuditLogSStripe()) {
           //Use built-in mechanism
           $attempt = new LoginAttempt();

           if($member) {
              $attempt->MemberID = $member->ID;
           } else {
              $attempt->MemberID = 0;
           }

           if ($success) {
               $attempt->Status = 'Success';
           } else {
               $attempt->Status = 'Failure';
           }

           $attempt->IP = Controller::curr()->getRequest()->getIP();
           $attempt->Email = $anchor . '@' . $source_id;
           $attempt->write();
       }

       if (!is_bool(self::getAuditLogFile())) {
           $logmessage = date(DATE_RFC822). ' - ';
           if ($success) $logmessage .= '[SUCCESS] '; else $logmessage .= '[FAILURE] ';
           $logmessage .= 'action ' . $action_type . ' for user ' . $anchor . ' at ' .
                          Controller::curr()->getRequest()->getIP() . ' from source ' .
                          $source_id;
           if (!is_null($because)) $logmessage .= ' because ' . $because;
           if (!@error_log($logmessage . "\n",3,self::getAuditLogFile())) {
               trigger_error('Unable to write logon attempt to ' . self::getAuditLogFile(), E_USER_ERROR);
           }
       }
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
      Object::add_extension('Member', 'ExternalAuthenticatedRole');
      Object::add_extension('Member_Validator', 'ExternalAuthenticatedRole_Validator');
      return parent::on_register();
  }



  /**
   * Check if the to authenticate user exists in the SilverStripe database and
   * load his/her record if present
   *
   * @param string $RAW_external_anchor   The users authentication source anchor
   * @param string $RAW_external_mailaddr The users mail address
   * @param string $RAW_external_source   The authentication source to use
   * @param string $form                  The login form
   *
   * @return string Query to get the Member object
   **/
  private static function getHandleToUse($RAW_external_anchor, $RAW_external_mailaddr, $RAW_external_source, $form) {
      if (self::getUseAnchor())
      {
          $SQL_source = Convert::raw2sql($RAW_external_source);

          // Anchor (if used) should not be empty
          // Password should not be empty as well, but we check this in the
          // external authentication method itself.
          if (strlen($RAW_external_anchor) == 0) {
              if (!is_null($form)) {
                  $form->sessionMessage(sprintf(_t('ExternalAuthenticator.EnterUID', 'Please enter a %s') ,self::$anchordesc), 'bad');
              }
              return false;
          }

          $SQL_anchor   = Convert::raw2sql($RAW_external_anchor);
          $memberquery = "\"Member\".\"External_Anchor\" = '$SQL_anchor' AND \"Member\".\"External_SourceID\" = '$SQL_source'";
      } else {
          if (strlen($RAW_external_mailaddr) == 0) {
              if (!is_null($form)) {
                  $form->sessionMessage(_t('ExternalAuthenticator.EnterMailAddr', 'Please enter an e-Mail address'), 'bad');
              }
              return false;
          }

          $SQL_mailaddr = Convert::raw2sql($RAW_external_mailaddr);
          $memberquery = "\"Member\".\"Email\" = '$SQL_mailaddr'";
      }

      return $memberquery;
  }


  /**
   * Check if a given authentication source is actually configured
   *
   * @param string $source  The source id
   * @param string $Log_ID  String to identify a line in the debug log
   * @param mixed  $member  Member object to use with the audit log or false
   *                        if no object is known
   *
   * @return boolean True if the source is configured
   **/
  private static function validSource($source, $Log_ID, $member = false) {
      if (is_bool(array_search($source,self::getSources()))) {
          self::AuthLog($Log_ID . ' - Source ' . $source . ' is not configured or client is not in permissible IP range');
          self::AuditLog($member, $Log_ID, 'logon', 'source does not exists' , false, $source);
          return false;
      } else {
          return true;
      }
  }


  /**
   * Check if a valid user account has been marked as locked out
   *
   * @param object $member   Valid member object
   * @param string $Log_ID   ID to use with the debug log
   *
   * @return boolean True is account is locked
   **/
  private static function accountLockedOut($member, $Log_ID) {
      if (self::getAuthSSLock($member->External_SourceID)) {
          self::AuthLog($Log_ID . ' - Password lock checking enabled');

          if ($member->isLockedOut()) {
              self::AuthLog($Log_ID . ' - User is locked out in Silverstripe Database');
              $member->registerFailedLogin();
              self::AuthLog($Log_ID . ' - This attempt is also logged in the database');

              self::AuditLog($member, $Log_ID, 'logon', 'account is locked' , false, $member->External_SourceID);
              return true;
          } else {
              self::AuthLog($Log_ID . ' - User is not locked');
              return false;
          }
      } else {
          self::AuthLog($Log_ID . ' - Password locking is disabled');
          return false;
      }
  }


  /**
   * Check if we can find the anchor for a given mail address in a
   * configured authentication source
   *
   * @param string $source                  The source to check
   * @param string $RAW_external_mailaddr   The given mail address
   * @param string $Log_ID                  ID to use with the debug log
   *
   * @return mixed  An array of source and anchor if found, false otherwise
   **/
  private static function locateAnchor($source, $RAW_external_mailaddr, $Log_ID) {
      self::AuthLog($Log_ID . ' - Using driver source ' . $source . ' to find anchor');
      $myauthenticator = strtoupper(self::getAuthType($source)) . '_Authenticator';
      $myauthenticator = new $myauthenticator();

      if ($RAW_external_anchor  = $myauthenticator->getAnchor($source,$RAW_external_mailaddr)) {
         self::AuthLog($Log_ID . ' - Found anchor ' . $RAW_external_anchor . ' in source ' . $source);
         $RAW_external_source = $source;
         return array('RAW_external_anchor' => $RAW_external_anchor,
                      'RAW_external_source' => $RAW_external_source);
      } else {
         self::AuthLog($Log_ID . ' - Did not find anchor for ' . $RAW_external_mailaddr . ' in source ' . $source);
         return false;
      }
  }


  /**
   * Check the group given against the group mapping table and return the best
   * matching group.
   *
   * Also verify that the group exists in silverstripe. Return false if the
   * group does not exist. This mimics the the behavior of not setting AutoAdd
   * at all
   *
   * @param string $source                The authentication source to use
   * @param string $groupinsrc            The group returned by the authentication
   *                                      source. (Could be null)
   *
   * @return object  An object containing the matching group or the last group from the
   *                 mapping table if no match is found
   **/
  private static function getMyGroup($source, $groupinsrc) {
      $autoadd     = self::getAutoAdd($source);
      $returngroup = false;

      // Is autoadd enabled?
      if (is_bool($autoadd)) {
          return false;
      }

      // Did the authentication source return a value?
      if (is_null($groupinsrc) && !is_array($autoadd)) {
          $returngroup = $autoadd;
      }

      // Return last group in the array if we didn't get any
      if (is_null($groupinsrc) && is_array($autoadd)) {
          $returngroup = array_pop($autoadd);
      }

      // A mapping array is defined. Does the given group exists in the mapping
      // table or do we return the last group as the default
      if (is_array($autoadd) && !is_null($groupinsrc)) {
          // Convert the key to uppercase for matching
          $autoadd = array_change_key_case($autoadd, CASE_UPPER);

          for ($count = 0; $count < count($autoadd); $count++) {
              if (array_key_exists($groupinsrc[$count], $autoadd)) {
                  $returngroup = $autoadd[$groupinsrc[$count]];
                  break;
              }
          }

          // If we didn't have a match, returngroup is still a boolean
          // Use the default (last) group from the mapping
          if (is_bool($returngroup)) {
              $returngroup = array_pop($autoadd);
          }
      } else {
          // No mapping table was set so return the default group
          $returngroup = $autoadd;
      }

      return self::groupObj($returngroup);
  }

  /**
   * Return a valid group object from flexibly input
   *
   * @param mixed  $group           (integer) group's ID
   *                                (string) group's code
   *                                (object) group object
   *
   * @return object                 Valid group object
   **/
  public static function groupObj($group) {
        if(is_numeric($group)) {
            $groupCheckObj = DataObject::get_by_id('Group', $group);
        } elseif(is_string($group)) {
            $SQL_group = Convert::raw2sql($group);
            $groupCheckObj = DataObject::get_one('Group', "\"Code\" = '{$SQL_group}'");
        } elseif($group instanceof Group) {
            $groupCheckObj = $group;
        } else {
            user_error('GroupExtended::groupObj(): Wrong format for $group parameter', E_USER_ERROR);
        }

    if(!$groupCheckObj) return false;
    return $groupCheckObj;
  }



  /**
   * Create an array to use for manipulating or creating the users' Member
   * object from the authentication results
   *
   * @param array  $RAW_result          The result from the sources'
   *                                    authenticate method
   * @param string $RAW_external_anchor The users' anchor
   * @param string $RAW_external_source The source where the anchor is located
   * @param string $RAW_domain          The mail domain of no e-mail address is
   *                                    present in the authenticate result
   *
   * @return array of string            An array with all needed user data
   **/
  private static function createMemberArray($RAW_result, $RAW_external_anchor, $RAW_external_source, $RAW_domain = null) {
      $SQL_memberdata = null;

      $SQL_memberdata['External_Anchor']   = Convert::raw2sql($RAW_external_anchor);
      $SQL_memberdata['External_SourceID'] = Convert::raw2sql($RAW_external_source);

      if (isset($RAW_result['firstname']) && !is_bool($RAW_result['firstname'])) {
          $SQL_memberdata['FirstName'] = Convert::raw2sql($RAW_result['firstname']);
      } else {
          $SQL_memberdata['FirstName'] = '';
      }

      if (isset($RAW_result['surname']) && !is_bool($RAW_result['surname'])) {
          $SQL_memberdata['Surname']   = Convert::raw2sql($RAW_result['surname']);
      } else {
          $SQL_memberdata['Surname']   = $RAW_external_anchor;
      }

      if (isset($RAW_result['email']) && !is_bool($RAW_result['email'])) {
          $SQL_memberdata['Email']     = Convert::raw2sql($RAW_result['email']);
      } else {
          if (is_null($RAW_domain)) {
              $SQL_memberdata['Email']     = $RAW_external_anchor;
          } else {
              $SQL_memberdata['Email']     = $RAW_external_anchor . '@' .
                                             Convert::raw2sql($RAW_domain);
          }
      }

      return $SQL_memberdata;
  }


  /**
   * When we fail login we should return the same state to the user always to prevent
   * giving hints on the reason of failure
   *
   */
  protected static function failmessage($form, $member, $Log_ID, $RAW_external_source) {
      if (!is_null($form)) {
          $form->sessionMessage(self::$authmessage,'bad');
      }
      self::AuditLog($member, $Log_ID, 'logon', NULL , false, $RAW_external_source);
  }

  /**
   * Method to authenticate an user
   *
   * @param $RAW_data Raw data to authenticate the user
   * @param Form $form Optional: If passed, better error messages can be
   *                             produced by using
   *                             {@link Form::sessionMessage()}
   * @return bool Returns FALSE if authentication fails, otherwise the
   *              member object
   */
  public static function authenticate($RAW_data, Form $form = null) {
      $RAW_external_anchor   = trim($RAW_data['External_Anchor']);
      $RAW_external_mailaddr = trim($RAW_data['External_MailAddr']);
      $RAW_external_source   = trim($RAW_data['External_SourceID']);
      $RAW_external_passwd   = $RAW_data['Password'];
      $userexists      = false;    //Does the user exist within SilverStripe?
      $userindbs       = false;    //Does the user already exist in the SStripe dbs?
      $authsuccess     = false;    //Initialization of variable

      //Set authentication message for failed authentication
      //Could be used by the individual drivers
      self::$authmessage = _t('ExternalAuthenticator.Failed', 'Authentication failed');

      self::AuthLog('Starting process for with alleged Anchor ' . $RAW_external_anchor .
                    ' and alleged mail ' . $RAW_external_mailaddr . ' at ' . self::$timestamp);

      if (($memberquery = self::getHandleToUse($RAW_external_anchor, $RAW_external_mailaddr, $RAW_external_source, $form))) {
          if ($member = DataObject::get_one('Member',$memberquery)) {
              $Log_ID = $member->Email;

              // Before we continue we must check if the source is valid
              if (!self::validSource($member->External_SourceID, $Log_ID, $member)) {
                  self::failmessage($form, $member, $Log_ID, $RAW_external_source);
                  return false;
              }

              $userexists = true;
              $userindbs  = true;

              self::AuthLog($Log_ID . ' - User with source ' . $member->External_SourceID . ' found in database');

              if (!self::getUseAnchor()) {
                  $RAW_external_source = stripslashes($member->External_SourceID);
                  $RAW_external_anchor = stripslashes($member->External_Anchor);
              }

              //Check if the user was behaving nicely
              if (self::accountLockedOut($member, $Log_ID)) {
                  self::failmessage($form, $member, $Log_ID, $RAW_external_source);
                  return false;
              }
          } else {
              $Log_ID = 'unknown';
              self::Authlog($Log_ID . ' - User with source NOT found in database');
          }
      } else {
          // Authentication form was not filled out properly
          return false;
      }

      if (!$userexists && self::getUseAnchor()) {
          if (self::validSource($RAW_external_source, $Log_ID)) {
              if (self::getAutoAdd($RAW_external_source)) {
                  $userexists = true;
              } else {
                  self::Authlog($Log_ID . ' - AutoAdd for source ' . $RAW_external_source . ' not enabled, aborting');
                  self::failmessage($form, $member, $Log_ID, $RAW_external_source);
                  return false;
              }
          } else {
              self::failmessage($form, $member, $Log_ID, $RAW_external_source);
              self::Authlog($Log_ID . ' - Illegal source ' . $RAW_external_source . ' or client not in valid IP range; aborting');
              return false;
          }
      }

      // Try to find our anchor, since we have none
      if (!$userexists && !self::getUseAnchor()) {
          foreach (self::getSources() as $source) {
              if (self::getAutoAdd($source)) {
                  $auth_type = strtoupper(self::getAuthType($source));
                  self::AuthLog($Log_ID . ' - loading driver ' . $auth_type);

                  //If we don't have a user yet and autoadd is on; try to find the anchor
                  if ($memberdata = self::locateAnchor($source, $RAW_external_mailaddr, $Log_ID)) {
                      extract($memberdata);
                      $userexists = true;
                      break;
                  }
              }
          }
      } else {
          // Load the correct driver
          if (!self::validSource($RAW_external_source, $Log_ID)) {
              $form->sessionMessage(_t('ExternalAuthenticator.Failed', 'Authentication failed'),'bad');
              self::Authlog($Log_ID . ' - Illegal source ' . $RAW_external_source . ' or client not in valid IP range; aborting');
              self::failmessage($form, $member, $Log_ID, $RAW_external_source);
              return false;
          }

          $auth_type = strtoupper(self::getAuthType($RAW_external_source));
          self::AuthLog($Log_ID . ' - loading driver ' . $auth_type);
      }

      if ($userexists) {
          $myauthenticator = $auth_type . '_Authenticator';
          $myauthenticator = new $myauthenticator();

          self::AuthLog($Log_ID . ' - executing authentication driver');
          $RAW_result = $myauthenticator->Authenticate($RAW_external_source, $RAW_external_anchor,
                                                       $RAW_external_passwd);

          if ($RAW_result) {
              $authsuccess = true;
              self::AuthLog($Log_ID . ' - authentication success');
          } else {
              self::AuthLog($Log_ID . ' - authentication driver ' . $auth_type . ' failed');
              if ($member && self::getAuthSSLock($RAW_external_source)) {
                  self::AuthLog($Log_ID . ' - Registering failed login');
                  $member->registerFailedLogin();
              }
          }
      }

      // Check if we need to do something with the groups
      if ($authsuccess) {
          // We're an array, so we need to do auto-mapping
          // first determine which group we should be a member of
          $usergroup = self::getMyGroup($RAW_external_source, $RAW_result['group']);

          if (!$userindbs && !is_bool($usergroup)) {
              $SQL_memberdata = self::createMemberArray($RAW_result, $RAW_external_anchor, $RAW_external_source,
                                                        self::getDefaultDomain($RAW_external_source));

              // First we check if the user's e-mail address has changed
              // we do this by checking if the anchor and source are already in the dbs
              // we do this only if the user used his mail address to authenticate
              // If the user does not exist we create a new member object
              if (!self::getUseAnchor()) {
                  // First we check if the user's e-mail address has changed
                  // we do this by checking if the anchor and source are already in the dbs
                  // we do this only if the user used his mail address to authenticate
                  // If the user does not exist we create a new member object
                  if (!$member = DataObject::get_one('Member', '"Member"."External_Anchor" = \'' . $SQL_memberdata['External_Anchor'] .
                                                               '\' AND "Member"."External_SourceID" = \'' .
                                                               $SQL_memberdata['External_SourceID'] . '\'')) {
                      $member = new Member;
                      self::AuthLog($Log_ID . ' - Anchor does not exist in database.');
                  } else {
                      self::AuthLog($Log_ID . ' - Anchor already present in the database but mail address is unknown. Changing mail address for this anchor');
                      $userindbs = true;
                      self::AuditLog($member, $Log_ID, 'modify', 'account exists', true, $RAW_external_source);
                  }
              } else {
                  // Now we check if the users e-mail address already exists. He
                  // did not authenticate himself with the mail address and we
                  // assume that if authentication was successful, he is owner
                  // of the address. This supports moving users from one source
                  // to another
                  if (!$member = DataObject::get_one('Member','"Email" = \'' . $SQL_memberdata['Email'] .'\'')) {
                      $member = new Member;
                      self::AuthLog($Log_ID . ' - Mail address does not exist in the database');
                  } else {
                      self::Authlog($Log_ID . ' - Mail address already present in the database, modifying existing account');
                      $userindbs = true;
                      self::AuditLog($member, $Log_ID, 'modify', 'account exists', true, $RAW_external_source);
                  }
              }

              // But before we write ourselves to the database we must check if
              // the group we are subscribing to exists
              if (!is_bool($usergroup)) {
                  $member->update($SQL_memberdata);
                  if (!$userindbs) {
                      $member->ID = null;
                  }
                  self::AuthLog($Log_ID . ' - start adding or modifying user');
                  $member->write();
                  self::AuthLog($Log_ID . ' - finished adding user to database');

                  if (!$userindbs) {
                      self::AuthLog($Log_ID . ' - start setting group membership to group ' . $usergroup->Title);
                      $member->Groups()->add($usergroup->ID);
                      self::AuthLog($Log_ID . ' - finished setting group membership');
                  }
                  self::AuditLog($member, $Log_ID, 'creation', NULL , true, $RAW_external_source);
              } else {
                  self::AuthLog($Log_ID . ' - The group to add the user to did not exist');
                  $authsuccess = false;
              }
          }

          if ($userindbs && !is_bool($usergroup)) {
              self::AuthLog($Log_ID . ' - Group membership will be set to ID ' . $usergroup->ID . ' name ' . $usergroup->Title);

              // User exists. We should check current group against group from config
              $memberships = $member->Groups()->getIdList();

              if (array_key_exists($usergroup->ID, $memberships)) {
                  self::AuthLog($Log_ID . ' - User is already a member of ' . $usergroup->Title);
              } else {
                  foreach ($memberships as $membership) {
                      self::AuthLog($Log_ID . ' - Erasing membership of group ' . $membership);
                      $member->Groups()->remove(self::groupObj($membership));
                      self::AuthLog($Log_ID . ' - Done erasing membership of group ' . $membership);
                  }

                  self::AuthLog($Log_ID . ' - setting membership of ' . $usergroup->Title);
                  self::Auditlog($member, $Log_ID, 'modify', 'current group membership does not match configuration', true, $RAW_external_source);
                  $member->Groups()->add($usergroup->ID);
                  self::AuthLog($Log_ID . ' - Done setting membership of ' . $usergroup->Title);
              }
          }
      }

      self::AuthLog('Process for user ' . $Log_ID . ' ended');
      if ($authsuccess) {
          Session::clear('BackURL');

          self::$authmessage = '';
          // Set the security message here. Else it will be shown on logout
          Session::set('Security.Message.message', self::$authmessage);
          Session::set('Security.Message.type', 'good');

          self::AuditLog($member, $Log_ID, 'logon', NULL , true, $RAW_external_source);
          return $member;
      } else {
          self::failmessage($form, $member, $Log_ID, $RAW_external_source);
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
      return Object::create('ExternalLoginForm', $controller, 'LoginForm');
  }


  /**
   * Get the name of the authentication method
   *
   * @return string Returns the name of the authentication method.
   */
  public static function get_name() {
      return _t('ExternalAuthenticator.Title','External Account');
  }
}

