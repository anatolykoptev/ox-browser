(function() {
    const OriginalWorker = Worker;
    const bootstrapCode = `
        Object.defineProperty(Object.getPrototypeOf(navigator), 'webdriver', {
            get: () => false, configurable: true, enumerable: true
        });
        Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {
            get: () => 8, configurable: true
        });
        Object.defineProperty(Navigator.prototype, 'deviceMemory', {
            get: () => 8, configurable: true
        });
        Object.defineProperty(Navigator.prototype, 'platform', {
            get: () => 'MacIntel', configurable: true
        });
        Object.defineProperty(Navigator.prototype, 'languages', {
            get: () => Object.freeze(['en-US', 'en']), configurable: true
        });
    `;
    window.Worker = function(url, options) {
        try {
            if (url instanceof Blob) {
                return new OriginalWorker(url, options);
            }
            const urlStr = (typeof url === 'object' && url instanceof URL) ? url.href : String(url);
            if (urlStr.startsWith('blob:')) {
                return new OriginalWorker(url, options);
            }
            if (options && options.type === 'module') {
                return new OriginalWorker(url, options);
            }
            const blob = new Blob(
                [bootstrapCode + ';\nimportScripts("' + urlStr.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '");'],
                { type: 'application/javascript' }
            );
            return new OriginalWorker(URL.createObjectURL(blob), options);
        } catch(e) {
            return new OriginalWorker(url, options);
        }
    };
    window.Worker.prototype = OriginalWorker.prototype;
    Object.defineProperty(window.Worker, 'name', { value: 'Worker' });
})();
