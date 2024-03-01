var url = require('url');

const id = pm.variables.get('id');
const key = pm.variables.get('key');
const authorizationScheme = 'VERACODE-HMAC-SHA-256';
const requestVersion = "vcode_request_version_1";
const nonceSize = 16;

function computeHashHex(message, key_hex) {
    return CryptoJS.HmacSHA256(message, CryptoJS.enc.Hex.parse(key_hex)).toString(CryptoJS.enc.Hex);
}
function calulateDataSignature(key, nonceBytes, dateStamp, data) {
    let kNonce = computeHashHex(nonceBytes, key);
    let kDate = computeHashHex(dateStamp, kNonce);
    let kSig = computeHashHex(requestVersion, kDate);
    return computeHashHex(data, kSig);
}
function newNonce() {
    return CryptoJS.lib.WordArray.random(nonceSize).toString().toUpperCase();
}
function toHexBinary(input) {
    return CryptoJS.enc.Hex.stringify(CryptoJS.enc.Utf8.parse(input));
}
function calculateVeracodeAuthHeader(httpMethod, requestUrl) {
    let urlExpanded = requestUrl;
    while(urlExpanded.indexOf('{{') >= 0) {
        let variableName = urlExpanded.substring(urlExpanded.indexOf('{{')+2, urlExpanded.indexOf('}}'));
        let variableValue = pm.variables.get(variableName);
        urlExpanded = urlExpanded.replace('{{'+variableName+'}}', variableValue);
    }
    let parsedUrl = url.parse(urlExpanded);
    let data = `id=${id}&host=${parsedUrl.hostname}&url=${parsedUrl.path}&method=${httpMethod}`;
    let dateStamp = Date.now().toString();
    let nonceBytes = newNonce(nonceSize);
    let dataSignature = calulateDataSignature(key, nonceBytes, dateStamp, data);
    let authorizationParam = `id=${id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    let header = authorizationScheme + " " + authorizationParam;
    return header;
}
pm.request.headers.add({
    key: 'Authorization',
    value: calculateVeracodeAuthHeader(request['method'], request['url'])
});
