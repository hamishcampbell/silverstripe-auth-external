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

        if ($enc == 'ssl') {
            $conn = @ftp_ssl_connect(ExternalAuthenticator::getAuthServer($source), $port);
        } else {
            $conn = @ftp_connect(ExternalAuthenticator::getAuthServer($source), $port);
        }

        if (!$conn) {
            ExternalAuthenticator::setAuthMessage(_t('FTP_Authenticator.NoConnect','Could not connect to FTP server'));
            return false;
        }

        if (!@ftp_login($conn, $external_uid, $external_passwd)) {
            ftp_close($conn);
            ExternalAuthenticator::setAuthMessage(_t('ExternalAuthenticator.Failed'));
            return false;
        } else {
            ftp_close($conn);
            return true;
        }
    }
}
        
