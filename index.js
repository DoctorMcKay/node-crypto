var Crypto = require('crypto');

exports.Cipher = {
	"AES256CTR": 1,
	"AES256CTRWithHMAC": 2
};

var Flags = {
	"IsString": (1 << 0)
};

const MAGIC = 0xFADE;

/**
 * Make sure a buffer is a well-formed output of this module.
 * @param {Buffer} buffer
 * @returns {boolean}
 */
exports.isWellFormed = function(buffer) {
	// Minimum buffer size is 4 bytes. 2 bytes for magic, 1 for flags, 1 for cipher type
	if (buffer.length < 4) {
		return false;
	}

	if (buffer.readUInt16BE(0) != MAGIC) {
		return false;
	}

	// Make sure it's a valid cipher
	var cipher = buffer.readUInt8(3);
	var cipherValid = false;

	for (var i in exports.Cipher) {
		if (exports.Cipher.hasOwnProperty(i) && exports.Cipher[i] == cipher) {
			cipherValid = true;
			break;
		}
	}

	if (!cipherValid) {
		return false;
	}

	// Cipher-specific checks
	if (cipher == exports.Cipher.AES256CTR) {
		// Needs a 128-bit (16 bytes) IV
		if (buffer.length < 20) {
			return false;
		}
	}

	return true;
};

/**
 * Encrypt some data.
 * @param {number} cipher - One of the Cipher constants
 * @param {string|Buffer} key - Either a Buffer or a UTF-8 string
 * @param {string|Buffer} data - Either a Buffer or a UTF-8 string
 */
exports.encrypt = function(cipher, key, data) {
	if (typeof key === 'string') {
		key = new Buffer(key, 'utf8');
	}

	key = Crypto.createHash('sha256').update(key).digest();
	var flags = 0;

	if (typeof data === 'string') {
		flags |= Flags.IsString;
		data = new Buffer(data, 'utf8');
	}

	var iv, cipheriv, encrypted, output, hmac, temp;

	switch (cipher) {
		case exports.Cipher.AES256CTR:
			// Generate the IV
			iv = Crypto.randomBytes(16);
			cipheriv = Crypto.createCipheriv('aes-256-ctr', key, iv);
			encrypted = Buffer.concat([cipheriv.update(data), cipheriv.final()]);

			output = new Buffer(5 + iv.length + encrypted.length);
			output.writeUInt16BE(MAGIC, 0);
			output.writeUInt8(flags, 2);
			output.writeUInt8(cipher, 3);
			output.writeUInt8(iv.length, 4);
			iv.copy(output, 5);
			encrypted.copy(output, 5 + iv.length);
			return output;

		case exports.Cipher.AES256CTRWithHMAC:
			iv = Crypto.randomBytes(16);
			cipheriv = Crypto.createCipheriv('aes-256-ctr', key, iv);
			encrypted = Buffer.concat([cipheriv.update(data), cipheriv.final()]);

			temp = new Buffer(1);
			temp.writeUInt8(flags, 0);

			hmac = Crypto.createHmac('sha1', key.slice(0, 16)); // only use the first 128 bits for the hmac
			hmac.update(Buffer.concat([temp, iv, encrypted]));
			hmac = hmac.digest();

			output = new Buffer(5 + iv.length + encrypted.length + hmac.length);
			output.writeUInt16BE(MAGIC, 0);
			output.writeUInt8(flags, 2);
			output.writeUInt8(cipher, 3);
			output.writeUInt8(iv.length, 4);
			iv.copy(output, 5);
			encrypted.copy(output, 5 + iv.length);
			hmac.copy(output, 5 + iv.length + encrypted.length);
			return output;
	}

	throw new Error("Unknown cipher type");
};

/**
 * Decrypt some data.
 * @param {string|Buffer} key - Either a Buffer or a UTF-8 string
 * @param {Buffer} data - The encrypted package
 */
exports.decrypt = function(key, data) {
	if (!exports.isWellFormed(data)) {
		throw new Error("Invalid input data");
	}

	if (typeof key === 'string') {
		key = new Buffer(key, 'utf8');
	}

	key = Crypto.createHash('sha256').update(key).digest();

	var flags = data.readUInt8(2);
	var cipher = data.readUInt8(3);

	var iv, encrypted, hmac, decipher, decrypted;

	switch (cipher) {
		case exports.Cipher.AES256CTR:
			iv = data.slice(5, 5 + data.readUInt8(4));
			encrypted = data.slice(5 + iv.length);

			decipher = Crypto.createDecipheriv('aes-256-ctr', key, iv);
			decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
			if (flags & Flags.IsString) {
				return decrypted.toString('utf8');
			}

			return decrypted;

		case exports.Cipher.AES256CTRWithHMAC:
			// Verify the HMAC first
			iv = data.slice(5, 5 + data.readUInt8(4));
			encrypted = data.slice(5 + iv.length, data.length - 20);

			hmac = Crypto.createHmac('sha1', key.slice(0, 16));
			hmac.update(Buffer.concat([data.slice(2, 3), iv, encrypted]));
			hmac = hmac.digest();

			if (!hmac.equals(data.slice(data.length - 20))) {
				throw new Error("Mismatching HMAC");
			}

			decipher = Crypto.createDecipheriv('aes-256-ctr', key, iv);
			decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
			if (flags & Flags.IsString) {
				return decrypted.toString('utf8');
			}

			return decrypted;
	}

	throw new Error("Unknown cipher type");
};
