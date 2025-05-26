function FindProxyForURL(url, host) {
    // === Intranet Traffic - Bypass Proxy ===
    var isPrivateIP = /^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)/;
    if (isPrivateIP.test(host)) return "DIRECT";

    if  ((shExpMatch(host, "sts01*")) ||
	      (shExpMatch(host, "*.digicert.com*")) ||
	      (shExpMatch(host, "d32a6ru7mhaq0c.cloudfront.net")) ||
		  (shExpMatch(host, "*cso01*")) )
		{return "DIRECT";}

    if ((url.substring(0,5) != "http:") &&
                  (url.substring(0,4) != "ftp:") &&
                  (url.substring(0,6) != "https:"))
                  return "DIRECT";

    /        ====== Section IV ==== Bypasses for Zscaler ===================================

//        Go direct for queries about Zscaler infrastructure status 

          var trust = /^(trust|ips).(zscaler|zscalerone|zscalertwo|zscalerthree|zscalergov|zscloud).(com|net)$/;
          if (trust.test(host)) 
                  return "DIRECT";

//        ====== Section V ==== Bypasses for ZPA ===================================
		  /* test with ZPA*/
		  if (isInNet(resolved_ip, "100.64.0.0","255.255.0.0"))
			  return "DIRECT";


    if (isPlainHostName(host) ||
        shExpMatch(host, "*.reliancecapital.com") ||
        shExpMatch(host, "*.internal.company.com") ||
        shExpMatch(host, "intranet") ||
        shExpMatch(host, "intranet.company.com")) {
        return "DIRECT";
    }

    // === Zscaler infra that must be DIRECT (only basic diagnostics like gateway) ===
    if (shExpMatch(host, "gateway.zscloud.net") ||
        shExpMatch(host, "admin.zscaler.net") ||
        shExpMatch(host, "sfc.zscloud.net") ||
        shExpMatch(host, "sfc_lu.zscloud.net") ||
        shExpMatch(host, "*.zscloud.net") ||
        shExpMatch(host, "*.zscaler.net"))
{
        return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; PROXY 165.225.120.42:9400; PROXY 165.225.122.42:9400; DIRECT";
    }

    // === Everything else — including login.zscloud.net — goes via Zscaler ===
    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; PROXY 165.225.120.42:9400; PROXY 165.225.122.42:9400; DIRECT";
}
