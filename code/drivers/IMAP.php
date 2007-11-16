<?php
/**
 * IMAP/POP3 driver for the external authentication driver
 * This driver supports the SSL/TLS setting and the following options
 * A * means you _must_ set this option
 * *protocol      --> Protocol to use; imap or pop3
 * certnovalidate --> Do not validate the certificate when we use SSL/TLS
 *
 * @author Roel Gloudemans <roel@gloudemans.info> 
 */
 
class IMAP_Authenticator {

    /**
     * The default IMAP portlist in case it is not defined
     */   
    protected static $portlist   = array('pop3' => array('tls'     => 110,
                                                         'ssl'     => 995,
                                                         'default' => 110),
                                         'imap' => array('tls'     => 143,
                                                         'ssl'     => 993,
                                                         'default' => 143));
                                                         
    /**
     * Tries to logon to the IMAP server with given id and password
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
        $servicetype = ExternalAuthenticator::getOption("protocol");
        if (is_null($servicetype) || !in_array(strtolower($servicetype),array("imap","pop3"))) {
            ExternalAuthenticator::setAuthMessage(_t('IMAP_Authenticator.Protocol', 'Protocol is not set to a valid type'));
            return false;
        }

        $enc = ExternalAuthenticator::getAuthEnc();
        $port = ExternalAuthenticator::getAuthPort();
        if (is_null($port)) {
            if (is_null($enc)) {
                $port = self::$portlist["$servicetype"]["default"];
            } else {
                $port = self::$portlist["$servicetype"]["$enc"];
            }
        }
        
        $connectstring =  '{' . ExternalAuthenticator::getAuthServer();
        $connectstring .= ':' . $port;
        $connectstring .= '/' . $servicetype;
        
        if (!is_null($enc)) {
            $connectstring .= '/' . $enc;
            
            $validate = ExternalAuthenticator::getOption("certnovalidate");
            if (!is_null($validate) || $validate) {
                $connectstring .= '/novalidate-cert';
            }
        } else {
            $connectstring .= '/notls';
        }
        
        $connectstring .= '}';
        
        $mbox = @imap_open($connectstring, $external_uid, $external_passwd);
        if (!$mbox) {
            ExternalAuthenticator::setAuthMessage(_t('ExternalAuthenticator.Failed'));
            return false;
        } else {
            @imap_close($mbox);
            return true;
        }
    }            
}
