function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || 
        shExpMatch(host, "*.relianceada.com") ||
        shExpMatch(host, "*.ril.com") ||
        shExpMatch(host, "*.rinfra.com") ||
        shExpMatch(host, "reliancecapital.com"))
        return "DIRECT";

    var zscalerHosts = /^(trust|ips)\.(zscaler|zscalerone|zscloud)\.(com|net)$/;
    if (zscalerHosts.test(host))
        return "DIRECT";

    if ((url.substring(0,5) != "http:") && 
        (url.substring(0,6) != "https:"))
        return "DIRECT";

    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; DIRECT";
}
