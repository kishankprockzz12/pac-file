function FindProxyForURL(url, host) {
    // Simplified PAC file for iPad devices - Modified version
    
    // ====== Section I: Internal/Specific Destinations ======
    var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
    
    // If host is a private IP, send direct
    if (privateIP.test(host)) {
        return "DIRECT";
    }
    
    // ====== Section II: Protocol Handling ======
    // Send non-HTTP/HTTPS traffic direct
    if ((url.substring(0,5) != "http:") &&
        (url.substring(0,6) != "https:")) {
        return "DIRECT";
    }
    
    // ====== Section III: Zscaler Infrastructure ======
    var trust = /^(trust|ips)\.(zscaler|zscalerone|zscalertwo|zscalerthree|zscalergov|zscloud)\.(com|net)$/;
    if (trust.test(host)) {
        return "DIRECT";
    }
    
    // ====== Section IV: Mobile-Optimized Proxy Configuration ======
    // Using Zscaler cloud names instead of IPs for better reliability
    // Mobile-optimized proxy configuration with failover
    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; PROXY 165.225.120.42:9400; PROXY 165.225.122.42:9400; DIRECT";
}
