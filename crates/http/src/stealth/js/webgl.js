(function() {
    const spoofWebGL = (proto) => {
        const getParameter = proto.getParameter;
        proto.getParameter = function(parameter) {
            if (parameter === 37445) return 'Google Inc. (Intel)';
            if (parameter === 37446) return 'ANGLE (Intel, ANGLE Metal Renderer: Intel(R) UHD Graphics 630, Unspecified Version)';
            return getParameter.apply(this, arguments);
        };
    };
    spoofWebGL(WebGLRenderingContext.prototype);
    if (typeof WebGL2RenderingContext !== 'undefined') {
        spoofWebGL(WebGL2RenderingContext.prototype);
    }
})();
