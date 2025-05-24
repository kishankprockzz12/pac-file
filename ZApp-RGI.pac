function FindProxyForURL(url, host) {
    // Bypass Zscaler infrastructure domains
    if (shExpMatch(host, "gateway.zscloud.net") ||
        shExpMatch(host, "ip.zscaler.com") ||
        shExpMatch(host, "admin.zscaler.net") ||
        shExpMatch(host, "admin.zscloud.net") ||
        shExpMatch(host, "login.zscloud.net")) {
        return "DIRECT";
    }

    // Bypass for private IPs (intranet)
    var isPrivateIP = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/;
    if (isPrivateIP.test(host)) {
        return "DIRECT";
    }

    // Bypass internal domains
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.corp.local") ||
        shExpMatch(host, "*.intranet.company.com")) {
        return "DIRECT";
    }

    // Default: Zscaler proxy for Internet
    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; PROXY 165.225.120.42:9400; PROXY 165.225.122.42:9400; DIRECT";
}
