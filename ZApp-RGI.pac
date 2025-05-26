function FindProxyForURL(url, host) {
    var zscalerProxy = "PROXY 165.225.120.42:80:9400"; // Replace with actual Zscaler proxy

    // === Allow internal IPs / hostnames ===
    if (isPlainHostName(host) ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        dnsDomainIs(host, ".reliancecapital.com") ||
        dnsDomainIs(host, ".internal.company.com")) {
        return "DIRECT";
    }

    // === Allow Zscaler infrastructure for authentication ===
    var zscalerInfra = /^(trust|login|auth|ips)\.(zscaler|zscalerone|zscalertwo|zscalerthree|zscalergov|zscloud)\.(com|net)$/;
    if (zscalerInfra.test(host)) {
        return "DIRECT";
    }

    // === Route all HTTP/HTTPS traffic through Zscaler ===
    if (url.substring(0, 5) == "http:" || url.substring(0, 6) == "https:") {
        return zscalerProxy;
    }

    // === Block all other traffic ===
    return "PROXY 127.0.0.1:9";
}
