(function() {
    Object.defineProperty(Navigator.prototype, 'userAgentData', {
        get: () => ({
            brands: [
                { brand: "Google Chrome", version: "136" },
                { brand: "Chromium", version: "136" },
                { brand: "Not=A?Brand", version: "24" }
            ],
            mobile: false,
            platform: "macOS",
            getHighEntropyValues: async function(hints) {
                const values = {};
                for (const hint of hints) {
                    if (hint === 'platform') values.platform = "Windows";
                    else if (hint === 'platformVersion') values.platformVersion = "14.5.0";
                    else if (hint === 'architecture') values.architecture = "x86";
                    else if (hint === 'model') values.model = "";
                    else if (hint === 'bitness') values.bitness = "64";
                    else if (hint === 'fullVersionList') values.fullVersionList = [
                        { brand: "Google Chrome", version: "136.0.7103.92" },
                        { brand: "Chromium", version: "136.0.7103.92" },
                        { brand: "Not=A?Brand", version: "24.0.0.0" }
                    ];
                }
                return values;
            }
        }),
        configurable: true
    });
})();
