(function() {
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
        window.chrome.runtime.sendMessage = function() {
            return Promise.resolve(undefined);
        };
    }
    if (!window.chrome.csi) {
        window.chrome.csi = function() {
            const now = Date.now();
            return { startE: now, onloadT: now, pageT: now, tran: 15 };
        };
    }
    if (!window.chrome.loadTimes) {
        window.chrome.loadTimes = function() {
            const base = Date.now() / 1000;
            const jitter = () => Math.random() * 0.15;
            return {
                requestTime: base - 2.1 - jitter(),
                startLoadTime: base - 1.8 - jitter(),
                commitLoadTime: base - 1.5 - jitter(),
                finishDocumentLoadTime: base - 0.8 - jitter(),
                finishLoadTime: base - 0.3 - jitter(),
                firstPaintTime: base - 0.5 - jitter(),
                firstPaintAfterLoadTime: 0,
                navigationType: "Other",
                wasFetchedViaSpdy: true,
                wasNpnNegotiated: true,
                npnNegotiatedProtocol: "h2",
                wasAlternateProtocolAvailable: false,
                connectionInfo: "h2"
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
})();
