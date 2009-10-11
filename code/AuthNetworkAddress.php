<?php

/**
 * IP address juggler for the external authentication module
 * Used for restricting sources to certain client IP's
 * This Object IPv4 only, but will detect IPv6
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 */

class AuthNetworkAddress {

    protected static $ClientIP             = "";
    
    protected static $IsIPv6               = true;
    
    /**
     * Create the object and add the clients IP address to it
     * Determine if the client is IPv6
     **/
    function __construct() {
        self::$ClientIP = $_SERVER['REMOTE_ADDR'];
        
        // If no colons we have an IPv4 address for sure
        if (strpos(self::$ClientIP,':') === false) {
            self::$IsIPv6 = false;
            return 0;
        }
        
        // We could have an IPv4 address in disguise
        // it is either an ISATAP or embedded address
        // ::5EFE:a.b.c.d, ::0200:5EFE:a.b.c.d, ::ffff:a.b.c.d
        if (strpos(self::$ClientIP,'.') === 0) {
            return 0;
        }
        
        // So we have an IPv4 hidden in here
        self::$ClientIP = substr(self::$ClientIP,strrpos(self::$ClientIP,':')+1);
        self::$IsIPv6   = false;
        return 0;
    }
    
    /**
     * Return the clients IP address
     *
     * @return string  The IP
     **/    
    public static function getClientIP() {
        return self::$ClientIP;
    }
    
    /**
     * Check if the clients IP is in a given netmask or array of netmasks
     *
     * @param string  String with the netmask 
     *
     * @return boolean  True if client IP is in netmask
     **/
    public static function applyNetmask($netmask) {
        // We do not support IPv6 yet
        if (self::$IsIPv6) return false;
        
        // Determine mask length
        $netmask_parts = explode('/', $netmask);
        if (count($netmask_parts) > 2) return false;
        if (count($netmask_parts) < 1) return false;
        // Only one part, so we are dealing with a host here
        if (count($netmask_parts) == 1) $netmask_parts[1] = 32;
        
        // Now we detect the length of the netmask
        if (strpos($netmask_parts[1],'.') === true) {
            // Dot notation
            $netmask_parts[1] = strspn(sprintf("%032b", ip2long($netmask_parts[1])),"1");
        }
        
        if ($netmask_parts[1] > 0 && $netmask_parts[1] < 33) {
            // Thanks to jwadhams1 @ php.net ip2long documentation
            $client_ip_bin = sprintf("%032b",ip2long(self::$ClientIP));
            $net_ip_bin    = sprintf("%032b",ip2long($netmask_parts[0]));         
            return (substr_compare($client_ip_bin,$net_ip_bin,0,$netmask_parts[1]) === 0); 
        } else {
            return false;
        }
    }
}
