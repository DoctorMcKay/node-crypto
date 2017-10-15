const Crypto = require('crypto');

const Cipher = exports.Cipher = {
	"AES256CTRObsoleteDoNotUse": 1,
	"AES256CTR": 2, // formerly 1; now is an alias for AES256CTRWithHMAC
	"AES256CTRWithHMAC": 2 // Encrypt-then-MAC
};

const Flags = {
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

	for (var i in Cipher) {
		if (Cipher.hasOwnProperty(i) && Cipher[i] == cipher) {
			cipherValid = true;
			break;
		}
	}

	if (!cipherValid) {
		return false;
	}

	// Cipher-specific checks
	if ([Cipher.AES256CTRObsoleteDoNotUse, Cipher.AES256CTRWithHMAC].indexOf(cipher) == -1) {
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
		case Cipher.AES256CTRWithHMAC:
			iv = Crypto.randomBytes(16);
			cipheriv = Crypto.createCipheriv('aes-256-ctr', key, iv);
			encrypted = Buffer.concat([cipheriv.update(data), cipheriv.final()]);

			temp = new Buffer(1);
			temp.writeUInt8(flags, 0);

			hmac = Crypto.createHmac('sha1', key.slice(0, 16)); // only use the first 128 bits for the hmac
			hmac.update(Buffer.concat([temp, iv, encrypted]));
			hmac = hmac.digest();

			// 2 bytes = magic
			// 1 byte = flags
			// 1 byte = cipher ID
			// 1 byte = IV length
			// variable = IV
			// variable = ciphertext
			// 20 bytes = HMAC
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
 * @param {boolean} [expectAuthentication=false] - If true, will throw an Error if the data is not authenticated (e.g. with HMAC)
 */
exports.decrypt = function(key, data, expectAuthentication) {
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
		case Cipher.AES256CTRObsoleteDoNotUse:
		case Cipher.AES256CTRWithHMAC:
			var hasHmac = cipher == Cipher.AES256CTRWithHMAC;
			if (expectAuthentication && !hasHmac) {
				throw new Error("Expected authentication, but data was encrypted with AES256CTR without HMAC");
			}

			iv = data.slice(5, 5 + data.readUInt8(4));
			encrypted = data.slice(5 + iv.length, hasHmac ? data.length - 20 : undefined);

			// Verify the HMAC first
			if (hasHmac) {
				hmac = Crypto.createHmac('sha1', key.slice(0, 16));
				hmac.update(Buffer.concat([data.slice(2, 3), iv, encrypted]));
				hmac = hmac.digest();

				if (!hmac.equals(data.slice(data.length - 20))) {
					throw new Error("Mismatching HMAC");
				}
			}

			decipher = Crypto.createDecipheriv('aes-256-ctr', key, iv);
			decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
			break;

		default:
			throw new Error("Unknown cipher type");
	}

	if (flags & Flags.IsString) {
		return decrypted.toString('utf8');
	} else {
		return decrypted;
	}
};
