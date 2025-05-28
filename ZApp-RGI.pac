function FindProxyForURL(url, host) {
    // Simple private network bypass
    var privateIP = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/;
    if (privateIP.test(host) || isPlainHostName(host)) return "DIRECT";

    // Trusted internal domains bypass
    if (shExpMatch(host, "*.reliancecapital.com") ||
        shExpMatch(host, "*.internal.company.com")) {
        return "DIRECT";
    }

    // Zscaler diagnostic and auth domains via proxy
    if (shExpMatch(host, "*.zscloud.net") || shExpMatch(host, "*.zscaler.net")) {
        return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80";
    }

    // Route all other traffic through Zscaler; block if unauthenticated
    return "PROXY 165.225.120.42:9443; PROXY 165.225.122.42:9443; PROXY 127.0.0.1:9";
}
