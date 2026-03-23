(function() {
    // === ox-browser stealth bootstrap ===
    // Based on chaser-oxide by ccheshirecat (MIT)

    // 0. CDP Marker Cleanup
    for (const prop of Object.getOwnPropertyNames(window)) {
        if (/^cdc_|^\$cdc_|^__webdriver|^__selenium|^__driver|^\$chrome_/.test(prop)) {
            try { delete window[prop]; } catch(e) {}
        }
    }

    // Lock Error.prepareStackTrace to prevent CDP detection
    const originalPrepareStackTrace = Error.prepareStackTrace;
    let currentPrepareStackTrace = originalPrepareStackTrace;
    Object.defineProperty(Error, 'prepareStackTrace', {
        get() { return currentPrepareStackTrace; },
        set(fn) { /* blocked */ },
        configurable: true,
        enumerable: false
    });

    // 1. Platform (prototype-level to avoid getOwnPropertyNames detection)
    Object.defineProperty(Navigator.prototype, 'platform', {
        get: () => 'Win32', configurable: true
    });

    // 2. Hardware
    Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {
        get: () => 8, configurable: true
    });
    Object.defineProperty(Navigator.prototype, 'deviceMemory', {
        get: () => 8, configurable: true
    });
    Object.defineProperty(Navigator.prototype, 'maxTouchPoints', {
        get: () => 0, configurable: true
    });

    // 3. WebGL vendor/renderer spoofing
    const spoofWebGL = (proto) => {
        const getParameter = proto.getParameter;
        proto.getParameter = function(parameter) {
            if (parameter === 37445) return 'Google Inc. (NVIDIA)';
            if (parameter === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            return getParameter.apply(this, arguments);
        };
    };
    spoofWebGL(WebGLRenderingContext.prototype);
    if (typeof WebGL2RenderingContext !== 'undefined') {
        spoofWebGL(WebGL2RenderingContext.prototype);
    }

    // 4. Client Hints (UA-CH)
    Object.defineProperty(Navigator.prototype, 'userAgentData', {
        get: () => ({
            brands: [
                { brand: "Google Chrome", version: "136" },
                { brand: "Chromium", version: "136" },
                { brand: "Not=A?Brand", version: "24" }
            ],
            mobile: false,
            platform: "Windows",
            getHighEntropyValues: async function(hints) {
                const values = {};
                for (const hint of hints) {
                    if (hint === 'platform') values.platform = "Windows";
                    else if (hint === 'platformVersion') values.platformVersion = "19.0.0";
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

    // 5. Video Codecs
    const canPlayType = HTMLMediaElement.prototype.canPlayType;
    HTMLMediaElement.prototype.canPlayType = function(type) {
        if (type.includes('avc1')) return 'probably';
        if (type.includes('mp4a.40')) return 'probably';
        if (type === 'video/mp4') return 'probably';
        return canPlayType.apply(this, arguments);
    };

    // 6. WebDriver = false (prototype-level)
    Object.defineProperty(Object.getPrototypeOf(navigator), 'webdriver', {
        get: () => false, configurable: true, enumerable: true
    });

    // 7. Chrome Object
    if (!window.chrome) window.chrome = {};
    if (!window.chrome.runtime) window.chrome.runtime = {};

    if (!window.chrome.runtime.connect) {
        window.chrome.runtime.connect = function() {
            return {
                name: '', sender: undefined,
                onDisconnect: { addListener(){}, removeListener(){}, hasListener(){ return false; }, hasListeners(){ return false; } },
                onMessage: { addListener(){}, removeListener(){}, hasListener(){ return false; }, hasListeners(){ return false; } },
                postMessage(){}, disconnect(){}
            };
        };
    }
    if (!window.chrome.runtime.sendMessage) {
        window.chrome.runtime.sendMessage = function() { return; };
    }
    if (!window.chrome.csi) {
        window.chrome.csi = function() {
            const now = Date.now();
            return { startE: now, onloadT: now, pageT: now, tran: 15 };
        };
    }
    if (!window.chrome.loadTimes) {
        window.chrome.loadTimes = function() {
            const now = Date.now() / 1000;
            return {
                requestTime: now, startLoadTime: now, commitLoadTime: now,
                finishDocumentLoadTime: now, finishLoadTime: now, firstPaintTime: now,
                firstPaintAfterLoadTime: 0, navigationType: "Other",
                wasFetchedViaSpdy: false, wasNpnNegotiated: false,
                npnNegotiatedProtocol: "", wasAlternateProtocolAvailable: false,
                connectionInfo: "http/1.1"
            };
        };
    }
    if (!window.chrome.app) {
        window.chrome.app = {
            isInstalled: false,
            InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
            RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
            getDetails() { return null; }, getIsInstalled() { return false; }
        };
    }

    // 8. Navigator plugins (headless has empty plugins)
    Object.defineProperty(Navigator.prototype, 'plugins', {
        get: () => {
            const arr = [
                { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            ];
            arr.item = (i) => arr[i];
            arr.namedItem = (n) => arr.find(p => p.name === n);
            arr.refresh = () => {};
            return arr;
        },
        configurable: true
    });

    // 9. Permissions (headless returns 'denied' for notifications)
    const origQuery = Permissions.prototype.query;
    Permissions.prototype.query = function(desc) {
        if (desc.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission });
        }
        return origQuery.apply(this, arguments);
    };

    // 10. Worker thread injection
    const OriginalWorker = Worker;
    const bootstrapCode = `
        Object.defineProperty(Object.getPrototypeOf(navigator), 'webdriver', {
            get: () => false, configurable: true, enumerable: true
        });
        Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {
            get: () => 8, configurable: true
        });
    `;
    window.Worker = function(url, options) {
        const workerPromise = fetch(url)
            .then(res => res.text())
            .then(code => {
                const blob = new Blob([bootstrapCode + code], { type: 'application/javascript' });
                return new OriginalWorker(URL.createObjectURL(blob), options);
            });
        let realWorker = null;
        const pendingMessages = [];
        workerPromise.then(w => {
            realWorker = w;
            pendingMessages.forEach(msg => w.postMessage(msg));
        });
        return {
            postMessage(msg) {
                if (realWorker) realWorker.postMessage(msg);
                else pendingMessages.push(msg);
            },
            set onmessage(fn) { workerPromise.then(w => w.onmessage = fn); },
            terminate() { workerPromise.then(w => w.terminate()); }
        };
    };
})();
