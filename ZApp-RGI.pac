function FindProxyForURL(url, host) {
    // Bypass for private IPs (intranet) — so they go over VPN
    var isPrivateIP = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/;
    if (isPrivateIP.test(host)) {
        return "DIRECT";
    }

    // Bypass known internal domains (optional)
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.reliancecapital.com") ||
        shExpMatch(host, "*.intranet.company.com")) {
        return "DIRECT";
    }

    // Everything else goes via Zscaler proxy
    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; DIRECT";
}
