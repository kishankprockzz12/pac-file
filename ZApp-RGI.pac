function FindProxyForURL(url, host) {
    // === Intranet Traffic - Bypass Proxy (go through Citrix VPN) ===

    // Match private IP ranges
    var isPrivateIP = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/;
    if (isPrivateIP.test(host)) {
        return "DIRECT";
    }

    // Match internal hostnames or domains
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.corp.local") ||
        shExpMatch(host, "*.internal.company.com") ||
        shExpMatch(host, "intranet") ||
        shExpMatch(host, "intranet.company.com")) {
        return "DIRECT";
    }

    // === Zscaler Infrastructure - Bypass Proxy (for diagnostics/auth) ===
    if (shExpMatch(host, "gateway.zscloud.net") ||
        shExpMatch(host, "ip.zscaler.com") ||
        shExpMatch(host, "admin.zscaler.net") ||
        shExpMatch(host, "login.zscloud.net")) {
        return "DIRECT";
    }

    // === All other traffic - Use Zscaler proxy ===
    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; DIRECT";
}
