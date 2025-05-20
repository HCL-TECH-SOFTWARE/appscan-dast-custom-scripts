// Adds Basic HTTP authntication to the request
// Needs to be configured with 'Before request' context

/**
 * createBase64Encoder
 *
 * Returns a function that Base64-encodes arbitrary Unicode strings.
 *
 * @returns {function(string):string} A function which,
 *   given any JavaScript string, returns its Base64 representation.
 */
function createBase64Encoder() {
    var base64string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * utf8Encode
     *
     * Converts a JavaScript UTF-16 string into an array of UTF-8 code units (bytes).
     *
     * @param {string} str
     *   The input Unicode string.
     * @returns {number[]}
     *   An array of 8-bit numeric values representing the UTF-8 encoding.
     *
     * @internal
     */
    function utf8Encode(str) {
        var bytes = [];
        for (var n = 0; n < str.length; n++) {
            var c = str.charCodeAt(n);
            if (c < 128) {
                bytes.push(c);
            } else if (c < 2048) {
                bytes.push((c >> 6) | 192);
                bytes.push((c & 63) | 128);
            } else {
                bytes.push((c >> 12) | 224);
                bytes.push(((c >> 6) & 63) | 128);
                bytes.push((c & 63) | 128);
            }
        }
        return bytes;
    }

    /**
     * base64Encode
     *
     * Converts any Unicode string into a Base64‐encoded ASCII string.
     *
     * @param {string} str
     *   The input string to encode.
     * @returns {string}
     *   The Base64 representation of the input.
     */
    return function base64Encode(str) {
        var bytes = utf8Encode(str);
        var encoded = "";
        var i = 0;

        while (i < bytes.length) {
            var byte1 = bytes[i++];
            var byte2 = i < bytes.length ? bytes[i++] : 0;
            var byte3 = i < bytes.length ? bytes[i++] : 0;

            var chunk = (byte1 << 16) | (byte2 << 8) | byte3;

            var enc1 = (chunk >> 18) & 63;
            var enc2 = (chunk >> 12) & 63;
            var enc3 = (chunk >> 6) & 63;
            var enc4 = chunk & 63;

            encoded += base64string[enc1];
            encoded += base64string[enc2];
            encoded += base64string[enc3];
            encoded += base64string[enc4];
        }

        // Add padding '=' characters
        var remainder = bytes.length % 3;
        if (remainder === 1) {
            encoded = encoded.substring(0, encoded.length - 2) + "==";
        } else if (remainder === 2) {
            encoded = encoded.substring(0, encoded.length - 1) + "=";
        }

        return encoded;
    };
}

var base64Encode = createBase64Encoder();
var username = "";
var password = "";
var authString = username + ":" + password;
var encodedAuth = base64Encode(authString);
var basicAuthHeader = "Basic " + encodedAuth;
request.headers.set("Authorization", basicAuthHeader)
