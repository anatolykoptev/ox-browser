(function() {
    for (const prop of Object.getOwnPropertyNames(window)) {
        if (/^__playwright|^__pw|^cdc_|^\$cdc_|^__webdriver|^__selenium|^__driver|^\$chrome_/.test(prop)) {
            try { delete window[prop]; } catch(e) {}
        }
    }
    const originalPrepareStackTrace = Error.prepareStackTrace;
    let currentPrepareStackTrace = originalPrepareStackTrace;
    Object.defineProperty(Error, 'prepareStackTrace', {
        get() { return currentPrepareStackTrace; },
        set(fn) { /* blocked */ },
        configurable: true,
        enumerable: false
    });
})();
