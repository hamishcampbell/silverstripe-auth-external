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
    */
   protected static $useriddesc = 'User ID';

   /**
    * Message that results from authenticating
    **/
   protected static $authmessage = '';
   
   /**
    * Do let users choose the authentication source ot doe we check sources
    * in sequence? The order of the sequence bij the order in which the 
    * createSource is done (see below)
    **/
   protected static $authsequential = false;
   
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
           'useriddesc'    => 'User ID',    //How do we refer to a user id
           'encryption'    => null,         //Enable SSL or TLS encryption
           'autoadd'       => false,        //Automatically add users?
           'defaultdomain' => null,         //Default mail domain for auto 
                                            //adding accounts
                                            //Only works if driver cannot
                                            //get user mail.
           "authoption" => array()          //Driver specific options
       );
   }
   
   
   /**
    * Get all source ids
    *
    * return array Array of source id's
    **/
   public static function getSources() {
       return array_keys(self::$authsources);   
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
    * @param string $useriddesc Description of user id
    */                               
   public static function setIdDesc($useriddesc) {
       self::$useriddesc = $useriddesc;
   }
   
   /**
    * Get the user id description
    *
    * @return string useriddesc Description
    */              
   public static function getIdDesc() {
       return self::$useriddesc;
   }
   
   /** 
    * Set the authentication checks to sequential or user chosable
    *
    * @param bool $sequential
    **/
   public static function setAuthSequential($sequential) {
       self::$authsequential = $sequential;
   }
     
   /** 
    * Do we let the user choose or do we check sources in sequence
    *
    * @return bool True for sequential checks
    **/
   public static function getAuthSequential() {
       return self::$authsequential;
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
    * Writes a message to the debug logfile
    **/
   public static function AuthLog($message) {
       if (!is_bool(self::getAuthDebug())) {
           if (!@error_log(date(DATE_RFC822). ' - ' . $message . "\n",3,self::getAuthDebug())) {
               self::setAuthMessage(_t('ExternalAuthenticator.LogFailed', 'Logging to debug log failed'));
           }
       }
   }
   
   /**
    * Writes a message to the audit log
    *
    * @param object  $member       The member if found in the database
    * @param string  $user_id      The login name if the user
    * @param string  $action_type  What was tried?
    * @param string  $because      Reason for success
    * @param boolean $success      Did we succeed
    * @param string  $source_id    For which source
    **/
   public static function AuditLog($member, $user_id, $action_type, $because, $success, $source_id) {
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
           $attempt->Email = $user_id . '@' . $source_id;               
           $attempt->write();           
       }
       
       if (!is_bool(self::getAuditLogFile())) {
           $logmessage = date(DATE_RFC822). ' - ';
           if ($success) $logmessage .= '[SUCCESS] '; else $logmessage .= '[FAILURE] ';
           $logmessage .= 'action ' . $action_type . ' for user ' . $user_id . ' at ' . 
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
      if (self::getAuthSequential()) {
          $A_sources = self::getSources();
      } else {
          $A_sources = array($RAW_data['External_SourceID']);
      }
      $RAW_external_uid    = trim($RAW_data['External_UserID']);
      $RAW_external_passwd = $RAW_data['Password'];     
      $userexists      = false;    //Does the user exist within SilverStripe?
      $authsuccess     = false;    //Initialization of variable  
      //Set authentication message for failed authentication
      //Could be used by the individual drivers      
      self::$authmessage = _t('ExternalAuthenticator.Failed', 'Authentication failed');
  
      // User ID should not be empty
      // Password should not be empty as well, but we check this in the
      // external authentication method itself. 
      if (strlen($RAW_external_uid) == 0) {
          if (!is_null($form)) {
              $form->sessionMessage(sprintf(_t('ExternalAuthenticator.EnterUID', 'Please enter a %s') ,self::$useriddesc), 'bad');
          }
          return false;
      } 
      $SQL_identity = Convert::raw2sql($RAW_external_uid);
      
      self::AuthLog('Starting process for user ' . $SQL_identity);
           
      // Now we are going to check this user with each source from the source
      // array, until we succeed or utterly fail
      foreach ($A_sources as $RAW_source) {
          $SQL_source   = Convert::raw2sql($RAW_source);
          if (($member = DataObject::get_one('Member',"Member.External_UserID = '$SQL_identity'".
                                             " AND Member.External_SourceID = '$SQL_source'"))) {
              $userexists = true;
              self::AuthLog($SQL_identity . ' - User with source ' . $RAW_source . ' found in database');
              
              //Check if the user was behaving nicely
              if (self::getAuthSSLock($RAW_source)) {
                  self::AuthLog($SQL_identity . ' - Password lock checking enabled');
                  
                  if ($member->isLockedOut()) {
                      self::AuthLog($SQL_identity . ' - User is locked out in Silverstripe Database');
                      $member->registerFailedLogin();
                      self::AuthLog($SQL_identity . ' - This attempt is also logged in the database');
                      $form->sessionMessage(_t('ExternalAuthenticator.Failed'),'bad');
                      
                      self::AuditLog($member, $RAW_external_uid, 'logon', 'account is locked' , false, $RAW_source); 
                      return false;
                  } else {
                      self::AuthLog($SQL_identity . ' - User is not locked');
                  }
              } else {
                  self::AuthLog($SQL_identity . ' - Password locking is disabled');
              }    
          } else {
              self::Authlog($SQL_identity . ' - User with source ' . $RAW_source . ' NOT found in database');
          }
      
      
          if ($userexists || self::getAutoAdd($RAW_source)) {   
              $auth_type = strtoupper(self::getAuthType($RAW_source));

              self::AuthLog($SQL_identity . ' - loading driver ' . $auth_type);
              require_once 'drivers/' . $auth_type . '.php';
              $myauthenticator = $auth_type . '_Authenticator';
              $myauthenticator = new $myauthenticator();
              
              self::AuthLog($SQL_identity . ' - executing authentication driver');
              $RAW_result = $myauthenticator->Authenticate($RAW_source, $RAW_external_uid, 
                                                           $RAW_external_passwd);

              if ($RAW_result) {
                  $authsuccess = true;
                  self::AuthLog($SQL_identity . ' - authentication success');
                  break;
              } else {
                  self::AuthLog($SQL_identity . ' - authentication driver ' . $auth_type . ' failed');
                  if ($member && self::getAuthSSLock($RAW_source)) {
                      self::AuthLog($SQL_identity . ' - Registering failed login');
                      $member->registerFailedLogin();
                      
                      self::AuthLog($SQL_identity . ' - user existed. Not continuing with other sources (if any)');
                      //Member existed no point in continuing the loop
                      break;
                  }
              }
          }
      }
      
      // An external source verified our existence
      if ($authsuccess && !$userexists && self::getAutoAdd($RAW_source)) {
          // But SilverStripe denies our existence, so we add ourselves
          $SQL_memberdata['External_UserID']   = $SQL_identity;
          $SQL_memberdata['External_SourceID'] = $SQL_source;
          if(isset($RAW_result['firstname'])) {
              $SQL_memberdata['FirstName'] = Convert::raw2sql($RAW_result['firstname']);
          }

          if (isset($RAW_result['surname'])) {
              $SQL_memberdata['Surname']   = Convert::raw2sql($RAW_result['surname']);
          } else {
              $SQL_memberdata['Surname']   = $SQL_identity;
          }
 
          if (isset($RAW_result['email'])) {
              $SQL_memberdata['Email']     = Convert::raw2sql($RAW_result['email']);
          } else {
              $RAW_domain = self::getDefaultDomain($RAW_source);
              if (is_null($RAW_domain)) {
                  $SQL_memberdata['Email']     = $SQL_identity;
              } else {
                  $SQL_memberdata['Email']     = $SQL_identity . '@' .
                                                 Convert::raw2sql($RAW_domain);
              }
          }

          // But before we write ourselves to the database we must check if
          // the group we are subscribing to exists
          self::AuthLog($SQL_identity . ' - User did not exist but did authenticate. Adding user to database');
          if ($group = DataObject::get_one('Group','Group.Title = \'' . Convert::raw2sql(self::getAutoAdd($RAW_source)).'\'')) {
              if (DataObject::get_one('Member','Email = \'' . $SQL_memberdata['Email'] .'\'')) {
                  self::$authmessage = _t('ExternalAuthenticator.GroupExists','An account with your e-mail address already exists');
                  $authsuccess = false;
              } else {
                  $member = new Member;

                  $member->update($SQL_memberdata);
                  $member->ID = null;
                  $member->write();
                  
                  self::AuthLog($SQL_identity . ' - start adding user to database');          
                  Group::addToGroupByName($member, $group->Code);
                  self::AuthLog($SQL_identity . ' - finished adding user to database');   
                  self::AuditLog($member, $RAW_external_uid, 'creation', NULL , true, $RAW_source); 
              }
          } else {
              self::AuthLog($SQL_identity . ' - The group to add the user to did not exist');          
              $authsuccess = false;
          }
      }

      self::AuthLog('Process for user ' . $SQL_identity . ' ended');
      if ($authsuccess) {
          Session::clear('BackURL');
          
          // Set the security message here. Else it will be shown on logout
          Session::set('Security.Message.message', self::$authmessage);
          Session::set('Security.Message.type', 'good');
          
          self::AuditLog($member, $RAW_external_uid, 'logon', NULL , true, $RAW_source); 
          return $member;
      } else {
          if(!is_null($form)) {   
              $form->sessionMessage(self::$authmessage,'bad');
          }
          
          self::AuditLog($member, $RAW_external_uid, 'logon', NULL , false, $RAW_source); 
                                
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

