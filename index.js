'use strict';

const AvastClient = require('avast-client');
const Transform = require('stream').Transform;
const PassThrough = require('stream').PassThrough;

class Scanner extends Transform {
    constructor(app, envelope) {
        super();

        this.envelope = envelope;

        this.scanner = new AvastClient({
            address: app.config.socket,
            tmpdir: app.config.tmpdir,
            logger: app.logger
        });

        this.message = new PassThrough();

        this.errored = false;
        this.processed = false;
        this.scanned = false;

        this.waiting = false;

        this.message.once('error', err => {
            this.scanned = true;
            this.errored = err;
            app.logger.info('Avast', '%s AVSCANFAIL error=%s', envelope.id, err.message);
        });

        this.scanner.scan('message.eml', this.message, (err, result) => {
            this.scanned = true;
            this.scanner.quit();

            console.log(err || result);

            if (err) {
                this.errored = err;
                app.logger.info('Avast', '%s AVSCANFAIL error=%s', envelope.id, err.message);
            }

            if (result) {
                this.envelope.avast = result;
                app.logger.info('Avast', '%s AVSCANRES status=%s message=%s', envelope.id, result.status, result.message || 'OK');
            }

            if (typeof this.waiting === 'function') {
                let done = this.waiting;
                this.waiting = false;
                return done();
            }
        });
    }

    _transform(chunk, encoding, done) {
        if (this.errored) {
            return done(chunk);
        }

        if (!this.message.write(chunk)) {
            this.message.once('drain', () => done(null, chunk));
        } else {
            return done(null, chunk);
        }
    }

    _flush(done) {
        this.processed = true;
        if (this.scanned) {
            return done();
        }
        this.waiting = done;
    }
}

module.exports.title = 'Avast Virus Check';
module.exports.init = function(app, done) {
    app.addAnalyzerHook((envelope, source, destination) => {
        let interfaces = Array.isArray(app.config.interfaces) ? app.config.interfaces : [].concat(app.config.interfaces || []);
        if (!interfaces.includes(envelope.interface) && !interfaces.includes('*')) {
            return source.pipe(destination);
        }

        let scanner = new Scanner(app, envelope);

        source.pipe(scanner).pipe(destination);
        source.once('error', err => {
            destination.emit('error', err);
        });
    });

    app.addHook('message:queue', (envelope, messageInfo, next) => {
        let interfaces = Array.isArray(app.config.interfaces) ? app.config.interfaces : [].concat(app.config.interfaces || []);
        if ((!interfaces.includes(envelope.interface) && !interfaces.includes('*')) || !envelope.spam || !envelope.spam.default) {
            return next();
        }

        if (envelope.avast && envelope.avast.status === 'infected') {
            return next(app.reject(envelope, 'spam', messageInfo, '550 This message contains a virus and may not be delivered'));
        }

        next();
    });

    done();
};
