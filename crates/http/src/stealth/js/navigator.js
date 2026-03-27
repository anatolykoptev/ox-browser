(function() {
    Object.defineProperty(Navigator.prototype, 'platform', {
        get: () => 'Win32', configurable: true
    });
    Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {
        get: () => 8, configurable: true
    });
    Object.defineProperty(Navigator.prototype, 'deviceMemory', {
        get: () => 8, configurable: true
    });
    Object.defineProperty(Navigator.prototype, 'maxTouchPoints', {
        get: () => 0, configurable: true
    });
    Object.defineProperty(Object.getPrototypeOf(navigator), 'webdriver', {
        get: () => false, configurable: true, enumerable: true
    });
    Object.defineProperty(Navigator.prototype, 'languages', {
        get: () => Object.freeze(['en-US', 'en']), configurable: true
    });
    Object.defineProperty(Navigator.prototype, 'plugins', {
        get: () => {
            const mkPlugin = (name) => ({
                name, filename: 'internal-pdf-viewer',
                description: 'Portable Document Format', length: 1,
                item: () => ({type: 'application/pdf'}),
                namedItem: () => ({type: 'application/pdf'}),
                [Symbol.iterator]: function*() { yield {type: 'application/pdf'}; }
            });
            const arr = [
                mkPlugin('Chrome PDF Viewer'),
                mkPlugin('Chromium PDF Viewer'),
                mkPlugin('Microsoft Edge PDF Viewer'),
                mkPlugin('PDF Viewer'),
                mkPlugin('WebKit built-in PDF'),
            ];
            arr.item = (i) => arr[i];
            arr.namedItem = (n) => arr.find(p => p.name === n);
            arr.refresh = () => {};
            return arr;
        },
        configurable: true
    });
    Object.defineProperty(Navigator.prototype, 'mimeTypes', {
        get: () => {
            const pdf = {
                type: 'application/pdf', suffixes: 'pdf',
                description: 'Portable Document Format',
                enabledPlugin: { name: 'Chrome PDF Viewer' }
            };
            const arr = [pdf];
            arr.item = (i) => arr[i];
            arr.namedItem = (n) => arr.find(m => m.type === n) || null;
            return arr;
        },
        configurable: true
    });
    const origQuery = Permissions.prototype.query;
    Permissions.prototype.query = function(desc) {
        if (desc.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission });
        }
        return origQuery.apply(this, arguments);
    };
})();
