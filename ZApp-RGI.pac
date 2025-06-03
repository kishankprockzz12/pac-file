
function FindProxyForURL(url, host) {

//        ZAPP RGI PAC Version-2 file created on 26th January 2019

//        ****************************************************************************
//        This is an example PAC file that should be edited prior to being put to use.
//        ****************************************************************************
        
//        Consider the following:
//         - Keep production PAC files small. Delete all comments if possible
//         - Delete any examples or sections that do not fit your needs
//         - Consolidate bypass criteria into fewer if() statements if possible
//         - Be sure you are bypassing only traffic that *must* be bypassed
//         - Be sure to not perform any DNS resolution in the PAC
//         - Zscaler recommends sending bypassed internet traffic via on-premise proxy compared
//           to the internet directly

//        ====== Section I ==== Internal/Specific Destinations ============================== 

//        Most special use IPv4 addresses (RFC 5735) defined within this regex.
         var privateIP = /^(0|10|127|192.168|172.1[6789]|172.2[0-9]|172.3[01]|169.254|192.88.99)\.[0-9.]+$/;
		  var resolved_ip = dnsResolve(host);

//        If host specified is IP address, and it is private, send direct.
         if (privateIP.test(host))
                  return "DIRECT";

//        Specific destinations can be bypassed here. Example lines for host, and
//        domain provided. Replace with your specific information. Add internal 
//        domains that cannot be publicly resolved here.

//         if (isPlainHostName(host) || (host == "host.example.com") ||
//               shExpMatch(host, "*.example.com"))
//             return "DIRECT";

//        Some RCAP URLs bypassed from proxy 		
	 if  ((shExpMatch(host, "sts01*")) ||
	      (shExpMatch(host, "*.digicert.com*")) ||
	      (shExpMatch(host, "d32a6ru7mhaq0c.cloudfront.net")) ||
		  (shExpMatch(host, "*cso01*")) )
		{return "DIRECT";}

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

   
  //      if (shExpMatch(host,"*.office365.com")) 
 //       {
 //           return "PROXY 167.103.19.193:80;PROXY 165.225.120.44:80;DIRECT";  
 //       }

 //       if (shExpMatch(host,"*.microsoftonline.com")) 
  //      {
//            return "PROXY 167.103.19.193:80;PROXY 165.225.120.44:80;DIRECT";  
  //      }

//        If you have a website that is hosted both internally and externally,
//        and you want to bypass proxy for internal version only, use the following

//        if (shExpMatch(host, "internal.example.com"))
//        {
//                var resolved_ip = dnsResolve(host);
//                if (privateIP.test(resolved_ip))
//                        return "DIRECT";
//        }

//        ====== Section II ==== Special Bypasses for SAML============================== 

//        if (shExpMatch(host, "*.okta.com") || shExpMatch(host, "*.oktacdn.com"))
//                return "DIRECT";
                
//        if (shExpMatch(host, "my_iwa_server.my_example_domain.com"))
//                return "DIRECT";

//        ====== Section III ==== Bypasses for other protocols ============================

//        Send everything other than HTTP and HTTPS direct
//        Uncomment middle line if FTP over HTTP is enabled

   
		 
          if ((url.substring(0,5) != "http:") &&
                  (url.substring(0,4) != "ftp:") &&
                  (url.substring(0,6) != "https:"))
                  return "DIRECT";

//        ====== Section IV ==== Bypasses for Zscaler ===================================

//        Go direct for queries about Zscaler infrastructure status 

//          var trust = /^(trust|ips).(zscaler|zscalerone|zscalertwo|zscalerthree|zscalergov|zscloud).(com|net)$/;
          if (trust.test(host)) 
                  return "DIRECT";

//        ====== Section V ==== Bypasses for ZPA ===================================
		  /* test with ZPA*/
		  if (isInNet(resolved_ip, "100.64.0.0","255.255.0.0"))
			  return "DIRECT";
	
//        ====== Section VI ==== DEFAULT FORWARDING ================================ 

//        If your company has purchased dedicated port, kindly use that in this file.
//        Port 9400 is the default port followed by 80. If that does not resolve, we send directly:
        
 //          return "PROXY 165.225.120.44:80; PROXY 167.103.19.193:80; PROXY 165.225.120.44:9400; PROXY 167.103.19.193:9400; DIRECT";
 //         return "PROXY 165.225.122.42:80; PROXY 165.225.124.42:80; PROXY 165.225.122.42:9400; PROXY 165.225.124.42:9400; DIRECT";
             return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; PROXY 165.225.120.42:9400; PROXY 165.225.122.42:9400; DIRECT";
}
