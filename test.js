var McCrypto = require('./index.js');

var testData = "The quick brown fox jumps over the lazy dog.";
var testKey = "foo bar baz";

// Ensure everything works with strings
expectAuthenticationTest(testKey, testData, "strings");
encryptAndDecryptTest(testKey, testData, "strings");


// Ensure everything works with buffers
testData = new Buffer("The quick brown fox jumps over the lazy dog.", "ascii");
expectAuthenticationTest(testKey, testData, "buffers");
encryptAndDecryptTest(testKey, testData, "buffers");


function encryptAndDecryptTest(key, data, testType) {
	var encrypted = McCrypto.encrypt(McCrypto.Cipher.AES256CTRWithHMAC, key, data);
	console.log(encrypted);
	if (!McCrypto.isWellFormed(encrypted)) {
		throw new Error("Encrypted data is not well-formed!");
	}

	// Make sure it decrypts
	var decrypted = McCrypto.decrypt(key, encrypted);
	var isEqual = decrypted.equals ? decrypted.equals(data) : decrypted == data;
	if (!isEqual) {
		throw new Error("Decrypted data is not the same as encrypted data!");
	}

	if (typeof data !== typeof decrypted) {
		throw new Error("Type of decrypted data does not match type of input data!");
	}

	console.log("Everything seems fine with " + testType + ": " + decrypted);
}

function expectAuthenticationTest(key, data, testType) {
	var encrypted = McCrypto.encrypt(McCrypto.Cipher.AES256CTR, key, data);
	try {
		McCrypto.decrypt(key, encrypted, true);
	} catch (ex) {
		if (ex.message == "Expected authentication, but data was encrypted with AES256CTR without HMAC") {
			console.log("expectAuthentication passed for " + testType);
			return;
		} else {
			throw ex;
		}
	}

	throw Error("expectAuthentication failed for " + testType);
}
