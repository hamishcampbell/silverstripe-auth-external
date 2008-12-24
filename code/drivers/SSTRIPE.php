<?php
/**
 * SilverStripe driver for authentication
 * Uses the SilverStripe built-in authentication mechanism
 *
 * The code was mainly copied from:
 * sapphire/security/MemberAuthenticator.php
 *
 * @author Markus Lanthaler <markus@silverstripe.com>
 * @author Roel Gloudemans <roel@gloudemans.info> 
 */
 
class SSTRIPE_Authenticator {

    /**
     * Tries to logon using the credentials in the SilverStripe database
     *
     * @access public
     *
     * @param  string $source Authentication source to be used 
     * @param  string $external_uid    The ID entered
     * @param  string $external_passwd The password of the user
     *
     * @return boolean  True if the authentication was a success, false 
     *                  otherwise
     */
    public function Authenticate($RAW_source, $RAW_external_uid, $RAW_external_passwd) {
        $SQL_identity = Convert::raw2sql($RAW_external_uid);

        // Default login (see Security::setDefaultAdmin())
        if (Security::check_default_admin($RAW_external_uid, $RAW_external_passwd)) {
            ExternalAuthenticator::AuthLog($external_uid.'.sstripe - Logging on with an Administrator account');
            $member = Security::findAnAdministrator();
        } else {
            $SQL_source   = Convert::raw2sql($RAW_source);
            ExternalAuthenticator::AuthLog($external_uid.'.sstripe - Searching for user with source ' . $SQL_source . 
                                           ' in database');
            $member = DataObject::get_one("Member","Member.External_UserID = '$SQL_identity'" .
                                          " AND Member.External_SourceID = '$SQL_source'" .
                                          " AND Password IS NOT NULL");
                                          
            if ($member) {
                ExternalAuthenticator::AuthLog($external_uid.'.sstripe - User was found in database');
                if (($member->checkPassword($RAW_external_passwd) == false)) {
                    ExternalAuthenticator::AuthLog($external_uid.'.sstripe - Password authentication failed');
                    $member = null;
                } else {
                    ExternalAuthenticator::AuthLog($external_uid.'.sstripe - Password authentication succeeded');
                }
            } else {
                ExternalAuthenticator::AuthLog($external_uid.'.sstripe - User was NOT found in database');
            }
        }

        if ($member) {
            return true;
        } else {
            ExternalAuthenticator::setAuthMessage(_t('ExternalAuthenticator.Failed'));
            return false;
        }
    }
}
        
