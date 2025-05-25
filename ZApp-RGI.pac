function FindProxyForURL(url, host) {
    // ====== Section I: Internal/Specific Destinations ======================
    
    // Private IP ranges (RFC 5735)
    var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
    
    // If host is a private IP, send direct (will go through VPN)
    if (privateIP.test(host)) {
        return "DIRECT";
    }
    
    // ====== Section II: Bypass Rules for Specific Domains ==================
    
    // RCAP specific bypasses
    if ((shExpMatch(host, "sts01*")) ||
        (shExpMatch(host, "*.digicert.com*")) ||
        (shExpMatch(host, "d32a6ru7mhaq0c.cloudfront.net")) ||
        (shExpMatch(host, "*cso01*")) ||
        (shExpMatch(host, "tlu.dl.delivery.mp.microsoft.com")) ||
        (shExpMatch(host, "sftp.rcap.co.in")) ||
        (shExpMatch(host, "*.delve.office.com")) ||
        (shExpMatch(host, "*.rclhrssg.com")) ||
        (shExpMatch(host, "*.relianceada.com")) ||
        (shExpMatch(host, "*.rinfra.com")) ||
        (shExpMatch(host, "*.relianceinfo.com")) ||
        (shExpMatch(host, "*.ril.com")) ||
        (shExpMatch(host, "*.97")) ||
        (shExpMatch(host, "reliancecapital.com")) ||
        (shExpMatch(host, "reliancecapital.in")) ||
        (shExpMatch(host, "*.reliancegeneral.com")) ||
        (shExpMatch(host, "*.reliancegeneral.co.in")) ||
        (shExpMatch(host, "*.reliancecapital.*")) ||
        (shExpMatch(host, "*rclnewjoinee*.*")) ||
        (shExpMatch(host, "*.rmocs.com")) ||
        (shExpMatch(host, "*citrixapp*")) || // Important for Citrix VPN
        (shExpMatch(host, "*.dostikadum.com")) ||
        (shExpMatch(host, "*.reliancemoney.com")) ||
        (shExpMatch(host, "*.reliancemoney.in")) ||
        (shExpMatch(host, "rcsintranet.relianceada.com")) ||
        (shExpMatch(host, "rmfapp.reliancemf.com")) ||
        (shExpMatch(host, "*.reliancecommodities.co.in")) ||
        (shExpMatch(host, "*.rsec.co.in")) ||
        (shExpMatch(host, "*.rclhrservices.*")) ||
        (shExpMatch(host, "*.reliancesharedservices.*")) ||
        (shExpMatch(host, "mygoldplan.co.in")) ||
        (shExpMatch(host, "*corprights*")) ||
        (shExpMatch(host, "webcast.rcap.co.in")) ||
        (shExpMatch(host, "eiscr.camsonline.com")) ||
        (shExpMatch(host, "*.rgurukool.com")) ||
        (shExpMatch(host, "*myworld*")) ||
        (shExpMatch(host, "*rcfapptsvr*")) ||
        (shExpMatch(host, "*parivartan*")) ||
        (shExpMatch(host, "*.reliancelife.*")) ||
        (shExpMatch(host, "viking")) ||
        (shExpMatch(host, "leadershipblog.relianceada.com")) ||
        (shExpMatch(host, "rclpim.reliancecapital.com")) ||
        (shExpMatch(host, "continuousit.rcap.co.in")) ||
        (shExpMatch(host, "rclconnect.rcap.co.in")) ||
        (shExpMatch(host, "rcs-vstrmgmt.rcs.com")) ||
        (shExpMatch(host, "*.rcs.com")) ||
        (shExpMatch(host, "secure.paytm.in")) ||
        (shExpMatch(host, "pguat.paytm.com")) ||
        (shExpMatch(host, "gstasp.rcap.co.in")) ||
        (shExpMatch(host, "*.iib.gov.in")) ||
        (shExpMatch(host, "agencyportal.irdai.gov.in")) ||
        (shExpMatch(host, "gcuat.brobotinsurance.com")) ||
        (shExpMatch(host, "*.brobotinsurance.com")) ||
        (shExpMatch(host, "ukyc.brobotinsurance.com")) ||
        (shExpMatch(host, ".brobot.com")) ||
        (shExpMatch(host, "tmsbo.pmjay.gov.in")) ||
        (shExpMatch(host, "*.tmsbo.pmjay.gov.in")) ||
        (shExpMatch(host, "sso.gem.gov.in")) ||
        (shExpMatch(host, "ecourts.gov.in")) ||
        (shExpMatch(host, "policy.haritaib.com")) ||
        (shExpMatch(host, "rarcl.com"))) {
        return "DIRECT";
    }
    
    // ====== Section III: Protocol Handling ================================
    
    // Send non-HTTP/HTTPS traffic direct (will go through VPN)
    if ((url.substring(0,5) != "http:") &&
        (url.substring(0,4) != "ftp:") &&
        (url.substring(0,6) != "https:")) {
        return "DIRECT";
    }
    
    // ====== Section IV: Zscaler Infrastructure Bypasses ===================
    
    // Go direct for Zscaler infrastructure status queries
    var trust = /^(trust|ips).(zscaler|zscalerone|zscalertwo|zscalerthree|zscalergov|zscloud).(com|net)$/;
    if (trust.test(host)) {
        return "DIRECT";
    }
    
    // ====== Section V: ZPA Bypasses ======================================
    
    // Bypass ZPA traffic
    var resolved_ip = dnsResolve(host);
    if (isInNet(resolved_ip, "100.64.0.0","255.255.0.0")) {
        return "DIRECT";
    }
    
    // ====== Section VI: Default Forwarding ================================
    
    // All other traffic goes through Zscaler proxies
    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; PROXY 165.225.120.42:9400; PROXY 165.225.122.42:9400; DIRECT";
}
