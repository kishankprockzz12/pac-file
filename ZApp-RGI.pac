function FindProxyForURL(url, host) {
    // Intranet domains (bypass proxy so it goes through VPN)
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.corp.local") ||
        shExpMatch(host, "*.internal.company.com") ||
        shExpMatch(host, "intranet.company.com")) {
        return "DIRECT";
    }

    // Everything else (Internet) goes through Zscaler proxy
    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; DIRECT";
}
