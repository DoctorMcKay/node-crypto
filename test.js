const McCrypto = require('./index.js');

const TEST_KEY = "foo bar baz";

legacyAES256CTRTest();
expectAuthenticationTest();

// Ensure everything works with strings
var testData = "The quick brown fox jumps over the lazy dog.";
encryptAndDecryptTest(testData, "strings");


// Ensure everything works with buffers
testData = new Buffer("The quick brown fox jumps over the lazy dog.", "ascii");
encryptAndDecryptTest(testData, "buffers");


function encryptAndDecryptTest(data, testType) {
	var encrypted = McCrypto.encrypt(McCrypto.Cipher.AES256CTRWithHMAC, TEST_KEY, data);
	console.log(encrypted);
	if (!McCrypto.isWellFormed(encrypted)) {
		throw new Error("Encrypted data is not well-formed!");
	}

	// Make sure it decrypts
	var decrypted = McCrypto.decrypt(TEST_KEY, encrypted, true);
	var isEqual = decrypted.equals ? decrypted.equals(data) : decrypted == data;
	if (!isEqual) {
		console.log(decrypted);
		throw new Error("Decrypted data is not the same as encrypted data!");
	}

	if (typeof data !== typeof decrypted) {
		throw new Error("Type of decrypted data does not match type of input data!");
	}

	console.log("Everything seems fine with " + testType + ": " + decrypted.toString('hex'));
}

function expectAuthenticationTest() {
	var encrypted = new Buffer("fade01011093480061d6340d2c298bfc5b4e98d661d1957a647b1045088f14592fd35784c8e2a32727ff639276092cd45e7412b47d7d21eebec6944b778943fc6b", "hex");
	try {
		McCrypto.decrypt(TEST_KEY, encrypted, true);
	} catch (ex) {
		if (ex.message == "Expected authentication, but data was encrypted with AES256CTR without HMAC") {
			console.log("expectAuthentication passed");
			return;
		} else {
			throw ex;
		}
	}

	throw Error("expectAuthentication failed");
}

function legacyAES256CTRTest() {
	var encrypted = new Buffer("fade01011093480061d6340d2c298bfc5b4e98d661d1957a647b1045088f14592fd35784c8e2a32727ff639276092cd45e7412b47d7d21eebec6944b778943fc6b", "hex");
	if (McCrypto.decrypt(TEST_KEY, encrypted) != "The quick brown fox jumps over the lazy dog.") {
		throw new Error("Legacy AES256CTR decryption failed");
	} else {
		console.log("Legacy AES256CTR decryption passed");
	}
}
