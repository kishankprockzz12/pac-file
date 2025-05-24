function FindProxyForURL(url, host) {
    if (isPlainHostName(host)) {
        return "DIRECT";
    }

    if (shExpMatch(host, "*.google.com") ||
        shExpMatch(host, "*.apple.com") ||
        shExpMatch(host, "*.icloud.com")) {
        return "DIRECT";
    }

    var zscalerHosts = /^(trust|ips)\.(zscaler|zscalerone|zscloud)\.(com|net)$/;
    if (zscalerHosts.test(host)) {
        return "DIRECT";
    }

    if ((url.substring(0, 5) !== "http:") &&
        (url.substring(0, 6) !== "https:") &&
        (url.substring(0, 4) !== "ftp:")) {
        return "DIRECT";
    }

    return "PROXY 165.225.120.42:80; PROXY 165.225.122.42:80; DIRECT";
}
