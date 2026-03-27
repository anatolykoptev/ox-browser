(function() {
    const canPlayType = HTMLMediaElement.prototype.canPlayType;
    HTMLMediaElement.prototype.canPlayType = function(type) {
        if (type.includes('avc1')) return 'probably';
        if (type.includes('mp4a.40')) return 'probably';
        if (type === 'video/mp4') return 'probably';
        return canPlayType.apply(this, arguments);
    };
})();
