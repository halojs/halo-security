'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

exports.default = function (options = {}) {
    options = (0, _deepmerge2.default)((0, _deepmerge2.default)({}, DEFAULT_OPTIONS), options);

    let cspValue, hstsValue, xframeValue;

    if (options.csp.enabled) {
        let key, value;

        cspValue = [];

        for (key of Object.keys(options.csp)) {
            if (key === 'enabled' || key === 'report') {
                continue;
            }

            value = getCspValue(options.csp[key]);
            key = decamelize(key);
            cspValue.push(` ${key} ${value}`);
        }

        cspValue = cspValue.join(';').trim();
    }

    if (options.hsts.enabled) {
        hstsValue = `max-age=${options.hsts.maxAge}`;

        if (options.hsts.includeSubDomains) {
            hstsValue += '; includeSubDomains';
        }
    }

    if (options.xframe.enabled) {
        if (options.xframe.deny) {
            xframeValue = 'DENY';
        } else if (options.xframe.origin) {
            xframeValue = 'SAMEORIGIN';
        } else if (options.xframe.allowUrl) {
            xframeValue = `ALLOW-FROM ${options.xframe.allowUrl}`;
        }
    }

    return async function _security(ctx, next) {
        if (options.ip.enabled && !(0, _ipFilter2.default)(ctx.ip, options.ip.filter)) {
            ctx.status = 403;
            return;
        }

        if (options.csrf.enabled) {
            let csrfToken, csrfSecret, method, name;

            name = options.csrf.name;
            method = ctx.method.toUpperCase();
            csrfToken = ctx.headers['x-csrf-token'];
            csrfSecret = ctx.cookies.get(`${name}Key`);

            if (['POST', 'PUT', 'DELETE'].includes(method)) {
                if (!csrfToken || !csrfSecret) {
                    ctx.status = 403;
                    return;
                }

                if (!tokens.verify(csrfToken, csrfSecret)) {
                    ctx.status = 403;
                    return;
                }
            }

            csrfSecret = tokens.secretSync();
            csrfToken = tokens.create(csrfSecret);

            ctx.cookies.set(`${name}Key`, csrfSecret);
            ctx.cookies.set(name, csrfToken, { httpOnly: false });
        }

        if (options.csp.enabled) {
            if (options.csp.report) {
                ctx.set('Content-Security-Policy-Report-Only', cspValue);
            } else {
                ctx.set('Content-Security-Policy', cspValue);
            }
        }

        if (options.hsts.enabled) {
            ctx.set('Strict-Transport-Security', hstsValue);
        }

        if (options.noopen.enabled) {
            ctx.set('X-Download-Options', 'noopen');
        }

        if (options.nosniff.enabled) {
            ctx.set('X-Content-Type-Options', 'nosniff');
        }

        if (options.xframe.enabled) {
            ctx.set('X-Frame-Options', xframeValue);
        }

        if (options.xss.enabled) {
            ctx.set('X-XSS-Protection', '1; mode=block');
        }

        await next();
    };
};

var _csrf = require('csrf');

var _csrf2 = _interopRequireDefault(_csrf);

var _ipFilter = require('ip-filter');

var _ipFilter2 = _interopRequireDefault(_ipFilter);

var _deepmerge = require('deepmerge');

var _deepmerge2 = _interopRequireDefault(_deepmerge);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const tokens = new _csrf2.default(); // Thanks to:
//   - https://developer.mozilla.org/zh-CN/docs/Web/Security/CSP/Using_Content_Security_Policy
//   - https://developer.mozilla.org/zh-CN/docs/Security/HTTP_Strict_Transport_Security
//   - https://msdn.microsoft.com/zh-cn/library/jj542450(v=vs.85).aspx
//   - https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-Content-Type-Options
//   - https://developer.mozilla.org/zh-CN/docs/Web/HTTP/X-Frame-Options
//   - https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-XSS-Protection

const DEFAULT_OPTIONS = {
    ip: {
        filter: [],
        enabled: false
    },
    csrf: {
        enabled: false,
        name: 'csrfToken'
    },
    csp: {
        report: false,
        enabled: false
    },
    hsts: {
        enabled: false,
        includeSubDomains: false,
        maxAge: 365 * 24 * 60 * 60
    },
    noopen: {
        enabled: false
    },
    nosniff: {
        enabled: false
    },
    xframe: {
        deny: false,
        origin: false,
        enabled: false,
        allowUrl: false
    },
    xss: {
        enabled: false
    }
};

function getCspValue(values) {
    return values.join(' ').replace(/self/ig, "'self'").replace(/none/ig, "'none'").replace(/unsafe-eval/ig, "'unsafe-eval'").replace(/unsafe-inline/ig, "'unsafe-inline'");
}

function decamelize(str) {
    return str.split(/(?=[A-Z])/).join('-').toLowerCase();
}