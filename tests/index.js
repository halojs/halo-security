import koa from 'koa'
import test from 'ava'
import security from '../src'
import request from 'request'
import mount from 'koa-mount'

const req = request.defaults({ json: true })

test.cb('ip filter, no match filter rule, statusCode is 403', (t) => {
    let app = new koa()

    app.use(security({
        ip: { enabled: true, filter: ['192.168.1.1'] }
    }))

    app.listen(3000, '0.0.0.0')

    req.get('http://localhost:3000', (err, res, body) => {
        t.is(res.statusCode, 403)
        t.end()
    })
})

test.cb('ip filter, match filter rule, statusCode is 200', (t) => {
    let app = new koa()

    app.use(security({
        ip: { enabled: true, filter: ['127.0.0.1'] }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(3001, '0.0.0.0')

    req.get('http://localhost:3001', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.end()
    })
})

test.cb('CSRF, verify token and secret is true, statusCode is 200', (t) => {
    let app = new koa()
    
    app.use(security({
        csrf: { enabled: true }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(5000)

    req.get('http://localhost:5000', (err, res, body) => {
        let jar = request.jar()
        let [token, secret] = res.headers['set-cookie']

        token = token.substring(token.indexOf('=') + 1, token.indexOf(';'))
        secret = secret.substring(secret.indexOf('=') + 1, secret.indexOf(';'))
        
        jar.setCookie(request.cookie(`csrfTokenKey=${secret}`), 'http://localhost:5000')
        request.post({
            jar,
            json: true,
            method: 'POST',
            url: 'http://localhost:5000',
            headers: {
                'X-Csrf-Token': token
            }
        }, (err, res, body) => {
            t.is(res.statusCode, 200)
            t.deepEqual(body, { ok: 1 })
            t.end()
        })
    })
})

test.cb('CSRF, x-csrf-token header not found, statusCode is 403', (t) => {
    let app = new koa()
    let jar = request.jar()
    
    app.use(security({
        csrf: { enabled: true }
    }))

    app.listen(5001)

    jar.setCookie(request.cookie(`csrfTokenKey=def`), 'http://localhost:5001')
    request({
        jar,
        method: 'POST',
        url: 'http://localhost:5001'
    }, (err, res, body) => {
        t.is(res.statusCode, 403)
        t.end()
    })
})

test.cb('CSRF, verify token and secret is false, statusCode is 403', (t) => {
    let app = new koa()
    let jar = request.jar()
    
    app.use(security({
        csrf: { enabled: true }
    }))

    app.listen(5002)

    jar.setCookie(request.cookie(`csrfTokenKey=def`), 'http://localhost:5002')
    request({
        jar,
        method: 'POST',
        url: 'http://localhost:5002',
        headers: {
            'X-Csrf-Token': 'abc'
        }
    }, (err, res, body) => {
        t.is(res.statusCode, 403)
        t.end()
    })
})

test.cb('Content-Security-Policy', (t) => {
    let app = new koa()

    app.use(security({
        csp: {
            enabled: true,
            defaultSrc: ['self'],
            objectSrc: ['none'],
            scriptSrc: ['unsafe-eval', 'unsafe-inline', 'https://test.com']
        }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(4000)

    req.get('http://localhost:4000', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['content-security-policy'], "default-src 'self'; object-src 'none'; script-src 'unsafe-eval' 'unsafe-inline' https://test.com")
        t.end()
    })
})

test.cb('Content-Security-Policy-Report-Only', (t) => {
    let app = new koa()

    app.use(security({
        csp: {
            report: true,
            enabled: true,
            defaultSrc: ['self'],
            objectSrc: ['none'],
            scriptSrc: ['unsafe-eval', 'unsafe-inline', 'https://test.com'],
            reportUri: ['http://test.com']
        }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(4001)

    req.get('http://localhost:4001', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['content-security-policy-report-only'], "default-src 'self'; object-src 'none'; script-src 'unsafe-eval' 'unsafe-inline' https://test.com; report-uri http://test.com")
        t.end()
    })
})

test.cb('Strict-Transport-Security', (t) => {
    let app = new koa()

    app.use(security({
        hsts: { enabled: true, includeSubDomains: true }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(3002)

    req.get('http://localhost:3002', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['strict-transport-security'], 'max-age=31536000; includeSubDomains')
        t.end()
    })
})

test.cb('X-Download-Options', (t) => {
    let app = new koa()

    app.use(security({
        noopen: { enabled: true }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(3003)

    req.get('http://localhost:3003', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['x-download-options'], 'noopen')
        t.end()
    })
})

test.cb('X-Content-Type-Options', (t) => {
    let app = new koa()

    app.use(security({
        nosniff: { enabled: true }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(3004)

    req.get('http://localhost:3004', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['x-content-type-options'], 'nosniff')
        t.end()
    })
})

test.cb('X-Frame-Options, value is DENY', (t) => {
    let app = new koa()

    app.use(security({
        xframe: { enabled: true, deny: true }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(3005)

    req.get('http://localhost:3005', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['x-frame-options'], 'DENY')
        t.end()
    })
})

test.cb('X-Frame-Options, value is SAMEORIGIN', (t) => {
    let app = new koa()

    app.use(security({
        xframe: { enabled: true, origin: true }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(3006)

    req.get('http://localhost:3006', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['x-frame-options'], 'SAMEORIGIN')
        t.end()
    })
})

test.cb('X-Frame-Options, value is SAMEORIGIN', (t) => {
    let app = new koa()

    app.use(security({
        xframe: { enabled: true, allowUrl: 'http://test.com' }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(3007)

    req.get('http://localhost:3007', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['x-frame-options'], 'ALLOW-FROM http://test.com')
        t.end()
    })
})

test.cb('X-XSS-Protection', (t) => {
    let app = new koa()

    app.use(security({
        xss: { enabled: true }
    }))
    app.use(mount('/', async function(ctx, next) {
        ctx.body = { ok: 1 }
    }))

    app.listen(3008)

    req.get('http://localhost:3008', (err, res, body) => {
        t.is(res.statusCode, 200)
        t.deepEqual(body, { ok: 1 })
        t.is(res.headers['x-xss-protection'], '1; mode=block')
        t.end()
    })
})