<?php
/**
 * FTP driver for the external authentication driver
 * This driver supports the SSL setting.
 *
 * @author Roel Gloudemans <roel@gloudemans.info> 
 */
 
class FTP_Authenticator {

    /**
     * The default FTP portlist in case it is not defined
     */   
    protected static $port = 21;
    
    
    /**
     * Tries to find the anchor for a given mail address and source
     *
     * @access public
     *
     * @param string $source          The Authentication source to be used
     * @param string $mailaddr        The mail address entered
     *
     * @return mixed    Anchor as string or false if not found
     **/
    public function getAnchor($source, $mailaddr) {
        ExternalAuthenticator::AuthLog($mailaddr.'.ftp - Anchor lookup not supported by source ' . $source);
        return false;
    }

                                                         
    /**
     * Tries to logon to the FTP server with given id and password
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
    public function Authenticate($source, $external_uid, $external_passwd) {
        $enc = ExternalAuthenticator::getAuthEnc($source);
        $port = ExternalAuthenticator::getAuthPort($source);
        if (is_null($port)) {
            $port = self::$port;
        }

        ExternalAuthenticator::AuthLog($external_uid.'.ftp - Connecting to ' .
                                       ExternalAuthenticator::getAuthServer($source) . ' port ' . $port); 
        if ($enc == 'ssl') {
            ExternalAuthenticator::AuthLog($external_uid.'.ftp - Connection type is SSL'); 
            $conn = @ftp_ssl_connect(ExternalAuthenticator::getAuthServer($source), $port);
        } else {
            $conn = @ftp_connect(ExternalAuthenticator::getAuthServer($source), $port);
        }

        if (!$conn) {
            ExternalAuthenticator::AuthLog($external_uid.'.ftp - Connection to server failed'); 
            ExternalAuthenticator::setAuthMessage(_t('FTP_Authenticator.NoConnect','Could not connect to FTP server'));
            return false;
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.ftp - Connection to server succeeded');
        } 

        if (!@ftp_login($conn, $external_uid, $external_passwd)) {
            ExternalAuthenticator::AuthLog($external_uid.'.ftp - User credentials failed at ftp server');
            ftp_close($conn);
            ExternalAuthenticator::setAuthMessage(_t('ExternalAuthenticator.Failed'));
            return false;
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.ftp - ftp server validated credentials');
            ftp_close($conn);
            return true;
        }
    }
}
        
