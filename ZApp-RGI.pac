
function FindProxyForURL(url, host) {

    var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
    var resolved_ip = dnsResolve(host);
   // var country = "India";

    /* Don't send non-FQDN or private IP auths to us */
    if (isPlainHostName(host) || isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || privateIP.test(resolved_ip))
        return "DIRECT";

    /* FTP goes directly */
    if (url.substring(0,4) == "ftp:")
        return "DIRECT";
			
    /* test with ZPA */
    if (isInNet(resolved_ip, "100.64.0.0","255.255.0.0"))
        return "DIRECT";
			
    /* Updates are directly accessible */
    if (((localHostOrDomainIs(host, "trust.zscaler.com")) ||
            (localHostOrDomainIs(host, "trust.zscaler.net")) ||
            (localHostOrDomainIs(host, "trust.zscalerone.net")) ||
            (localHostOrDomainIs(host, "trust.zscalertwo.net")) ||
            (localHostOrDomainIs(host, "trust.zscalerthree.net")) ||
            (localHostOrDomainIs(host, "trust.zscalergov.net")) ||
            (localHostOrDomainIs(host, "trust.zsdemo.net")) ||
            (localHostOrDomainIs(host, "trust.zscloud.net")) ||
            (localHostOrDomainIs(host, "trust.zsfalcon.net")) ||
            (localHostOrDomainIs(host, "trust.zdxcloud.net")) ||
            (localHostOrDomainIs(host, "trust.zdxpreview.net")) ||
            (localHostOrDomainIs(host, "trust.zdxbeta.net")) ||
            (localHostOrDomainIs(host, "trust.zsdevel.net")) ||
            (localHostOrDomainIs(host, "trust.zsbetagov.net")) ||
			(localHostOrDomainIs(host, "trust.zspreview.net")) ||
			(localHostOrDomainIs(host, "trust.zscalerten.net")) || 
			(localHostOrDomainIs(host, "trust.zdxten.net")) ) &&
            (url.substring(0,5) == "http:" || url.substring(0,6) == "https:"))
        return "DIRECT";

	/* for users of Canada if you want to direct traffic to only canada gateways*/
//	if (shExpMatch(country, "Canada")) {
//	 	return "PROXY 165.225.120.45:80; PROXY 167.103.19.194:80;DIRECT";
//	}

	/* for all users if you want to direct traffic to country gateways by default */
//	return "PROXY 165.225.120.45:80; PROXY 167.103.19.194:80;DIRECT";


    /* Default Traffic Forwarding. Forwarding to Zen on port 80, but you can use port 9400 also */
    return "PROXY 165.225.120.45:443; PROXY 167.103.19.194:443; DIRECT";
}
