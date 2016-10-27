var McCrypto = require('./index.js');

var testData = "The quick brown fox jumps over the lazy dog.";
var testKey = "foo bar baz";

var encrypted = McCrypto.encrypt(McCrypto.Cipher.AES256CTRWithHMAC, testKey, testData);
console.log(encrypted);

if (!McCrypto.isWellFormed(encrypted)) {
	throw new Error("Encrypted data is not well-formed!");
}

var decrypted = McCrypto.decrypt(testKey, encrypted);
if (decrypted != testData) {
	throw new Error("Decrypted data is not the same as encrypted data!");
}

console.log("Everything seems to be fine with strings: " + decrypted);

testData = new Buffer("The quick brown fox jumps over the lazy dog.");

encrypted = McCrypto.encrypt(McCrypto.Cipher.AES256CTRWithHMAC, testKey, testData);
console.log(encrypted);

if (!McCrypto.isWellFormed(encrypted)) {
	throw new Error("Encrypted data is not well-formed!");
}

decrypted = McCrypto.decrypt(testKey, encrypted);
if (!decrypted.equals(testData)) {
	throw new Error("Decrypted data is not the same as encrypted data!");
}

console.log("Everything seems to be fine with buffers: " + decrypted);
