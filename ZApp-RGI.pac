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

//	     Bypass Reliance Capital Specific traffic completely from Zscaler
	 if 	((shExpMatch(host, "tlu.dl.delivery.mp.microsoft.com")) ||
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
		 (shExpMatch(host, "*citrixapp*")) ||
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
		 (shExpMatch(host, "rarcl.com")) )
		 {return "DIRECT";}

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
