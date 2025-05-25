function FindProxyForURL(url, host) {
    // === Intranet Traffic - Bypass Proxy ===
    var isPrivateIP = /^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)/;
    if (isPrivateIP.test(host)) return "DIRECT";

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
        return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; DIRECT";
    }

    // === Everything else — including login.zscloud.net — goes via Zscaler ===
    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; DIRECT";
}
