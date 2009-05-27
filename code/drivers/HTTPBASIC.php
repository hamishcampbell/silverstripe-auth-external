<?php
/**
 * HTTP driver for the external authentication driver
 * This driver supports the SSL setting.
 * This driver also has support for network proxy
 *
 * NOTE: The PEAR package HTTP_Request is mandatory
 *
 * @author Roel Gloudemans <roel@gloudemans.info> 
 */
 
class HTTPBASIC_Authenticator {
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
        ExternalAuthenticator::AuthLog($mailaddr.'.http - Anchor lookup not supported by source ' . $source);
        return false;
    }

    /**
     * Tries to logon to the HTTP server with given id and password
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
        require_once 'HTTP/Request.php';

        // Set some default HTTP request options
        $request_options['method']         = 'GET';
        $request_options['timeout']        = 5;
        $request_options['allowRedirects'] = true;

        $enc        = ExternalAuthenticator::getAuthEnc($source);
        $port       = ExternalAuthenticator::getAuthPort($source);
        $folder     = ExternalAuthenticator::getOption($source,'folder');
        $proxy      = ExternalAuthenticator::getOption($source,'proxy');
        $proxy_port = ExternalAuthenticator::getOption($source,'proxy_port');
        $proxy_user = ExternalAuthenticator::getOption($source,'proxy_user');
        $proxy_pass = ExternalAuthenticator::getOption($source,'proxy_pass');

        if (!is_null($proxy) && !is_null($proxy_port)) {
            ExternalAuthenticator::AuthLog($external_uid.'.http - Proxy is set to ' . $proxy . ':' . $proxy_port);
            $request_options['proxy_host'] = $proxy;
            $request_options['proxy_port'] = $proxy_port;
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.http - Proxy is not set');
        }  

        if (!is_null($proxy_user)) {
            ExternalAuthenticator::AuthLog($external_uid.'.http - Proxy user is set to ' . $proxy_user);
            $request_options['proxy_user'] = $proxy_user;
            if (!is_null($proxy_pass)) {
                ExternalAuthenticator::AuthLog($external_uid.'.http - Proxy password is set');
                $request_options['proxy_pass'] = $proxy_pass;
            } else {
                ExternalAuthenticator::AuthLog($external_uid.'.http - Proxy password is NOT set');
            }
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.http - Proxy user is NOT set');
        }

        if ($enc == 'ssl') {
            $url = 'https://';
        } else {
            $url = 'http://';
        }

        $url .= ExternalAuthenticator::getAuthServer($source);

        if (!is_null($port)) {
            $url .= ':' . $port;
        }

        if (!is_null($folder)) {
            $url .= $folder;
        }
        ExternalAuthenticator::AuthLog($external_uid.'.http - Authentication URL is set to ' . $url);

        $request = new HTTP_Request($url, $request_options);
        $request->setBasicAuth($external_uid, $external_passwd);
        
        ExternalAuthenticator::AuthLog($external_uid.'.http - Sending authentication request');
        $request->sendRequest();

        // HTTP code 200 means everything is OK
        if ($request->getResponseCode() == 200) {
            ExternalAuthenticator::AuthLog($external_uid.'.http - Remote server returned code 200');
            return true;
        } else {
            ExternalAuthenticator::AuthLog($external_uid.'.http - Authentication failed with HTTP code ' . $request->getResponseCode());
            ExternalAuthenticator::setAuthMessage(_t('ExternalAuthenticator.Failed'));
            return false;
        }
    }
}
        
