
/**
 * AES加密
 *
 * @param content 待加密的内容
 * @param secretKey 密钥
 * @param iv 初始向量
 * @returns {string} 加密结果
 */
function aesEncrypt(content, secretKey, iv) {
    return CryptoJS.AES.encrypt(content, CryptoJS.enc.Utf8.parse(secretKey), {
        iv: CryptoJS.enc.Utf8.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    }).toString();
}

/**
 * AES解密
 *
 * @param content 待解密的内容
 * @param secretKey 密钥
 * @param iv 初始向量
 * @returns {string} 解密结果
 */
function aesDecrypt(content, secretKey, iv) {
    return CryptoJS.AES.decrypt(content, CryptoJS.enc.Utf8.parse(secretKey), {
        iv: CryptoJS.enc.Utf8.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    }).toString(CryptoJS.enc.Utf8);
}

/**
 * RSA 公钥加密
 *
 * @param content 待加密数据
 * @param publicKey 公钥
 * @returns {string} 加密结果
 */
function rsaEncrypt(content, publicKey) {
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(publicKey);
    return encrypt.encrypt(content);
}

/**
 * RSA 私钥解密
 *
 * @param content 待解密数据
 * @param privateKey 私钥
 * @returns {string} 解密结果
 */
function rsaDecrypt(content, privateKey) {
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey(privateKey);
    return encrypt.decrypt(content);
}

$(function () {

    // 设置上下文路径
    var CONTEXT_PATH = '';

    $.get(CONTEXT_PATH + '/crypto', function (result) {

        // ---------- AES 部分 ----------
        $('.aes-key').text(result.aesKey);
        $('.aes-iv').text(result.aesIV);
        $('.aes-data').text(result.aesSrcData);
        $('.aes-java-encryption').text(result.aesEncrypt);
        $('.aes-java-decryption').text(result.aesDecrypt);
        $('.aes-js-encryption').text(aesEncrypt(result.aesSrcData, result.aesKey, result.aesIV));
        $('.aes-js-decryption').text(aesDecrypt(result.aesEncrypt, result.aesKey, result.aesIV));

        // ---------- RSA 部分 ----------
        $('.rsa-public-key').text(result.rsaPublicKey);
        $('.rsa-private-key').text(result.rsaPrivateKey);
        $('.rsa-data').text(result.rsaSrcData);

        // Java公钥加密，js私钥解密
        $('.rsa-java-pub-encryption').text(result.rsaEncrypt);
        $('.rsa-js-pri-decryption').text(rsaDecrypt(result.rsaEncrypt, result.rsaPrivateKey));

        // js公钥加密
        var encrypt = rsaEncrypt(result.rsaSrcData, result.rsaPublicKey);
        $('.rsa-js-pub-encryption').text(encrypt);

        // 提交后台，Java私钥解密并返回
        $.post(CONTEXT_PATH + '/rsaDecrypt', {cipherText: encrypt}, function (result) {
            $('.rsa-java-pri-decryption').text(result.decrypt);
        }, 'json');

    }, 'json');
});