package cn.huangxulin.encryption.utils;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

/**
 * RSA加解密、签名、验签的工具类
 *
 * @author hxulin
 */
public final class RSAUtils {

    /**
     * 字符编码
     */
    private static final String CHARACTER_ENCODING = "utf-8";

    /**
     * 加密算法
     */
    private static final String KEY_ALGORITHM = "RSA";

    /**
     * 签名算法
     */
    private static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /**
     * RSA单次加密的最大明文长度
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA单次解密的最大密文长度
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    private RSAUtils() {

    }

    /**
     * Base64编码
     */
    private static String encryptBASE64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Base64解码
     */
    private static byte[] decryptBASE64(String data) {
        return Base64.getDecoder().decode(data);
    }

    /**
     * 初始化密钥
     *
     * @return 随机生成的密钥对
     */
    public static KeyPair initKey() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGen.initialize(1024);
            return keyPairGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取公钥
     *
     * @param keyPair 密钥对对象
     * @return Base64编码的公钥
     */
    public static String getPublicKey(KeyPair keyPair) {
        return encryptBASE64(keyPair.getPublic().getEncoded());
    }

    /**
     * 获取私钥
     *
     * @param keyPair 密钥对对象
     * @return Base64编码的私钥
     */
    public static String getPrivateKey(KeyPair keyPair) {
        return encryptBASE64(keyPair.getPrivate().getEncoded());
    }

    /**
     * 使用公钥加密数据
     *
     * @param data 需要加密的原文
     * @param key  公钥
     * @return 加密后进行Base64的密文
     */
    public static String encryptByPublicKey(String data, String key) throws Exception {
        return encryptBASE64(encryptByPublicKey(data.getBytes(CHARACTER_ENCODING), key));
    }

    /**
     * 使用公钥加密数据
     *
     * @param data 需要加密的数据
     * @param key  公钥
     * @return 加密后的数据
     */
    public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
        return cryptoByPublicKey(Cipher.ENCRYPT_MODE, data, decryptBASE64(key));
    }

    /**
     * 使用公钥解密数据
     *
     * @param data 需要解密的密文
     * @param key  公钥
     * @return 解密后的明文
     */
    public static String decryptByPublicKey(String data, String key) throws Exception {
        return new String(decryptByPublicKey(decryptBASE64(data), key), CHARACTER_ENCODING);
    }

    /**
     * 使用公钥解密数据
     *
     * @param data 需要解密的数据
     * @param key  公钥
     * @return 解密后的数据
     */
    public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
        return cryptoByPublicKey(Cipher.DECRYPT_MODE, data, decryptBASE64(key));
    }

    /**
     * 内部使用，使用公钥加解密数据
     *
     * @param opmode   模式
     * @param data     数据
     * @param keyBytes 密钥的字节数组
     * @return 加解密的结果
     * @throws Exception 加解密失败
     */
    private static byte[] cryptoByPublicKey(int opmode, byte[] data, byte[] keyBytes) throws Exception {
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据进行加解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(opmode, publicKey);
        return handleResult(opmode, data, cipher);
    }

    /**
     * 内部使用，RSA加解密数据有长度限制，此处对数据做分段处理
     *
     * @return 处理结果
     * @throws Exception 处理出错
     */
    private static byte[] handleResult(int opmode, byte[] data, Cipher cipher) throws Exception {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        int maxHandleLength = opmode == Cipher.ENCRYPT_MODE ? MAX_ENCRYPT_BLOCK : MAX_DECRYPT_BLOCK;
        while (inputLen > offset) {
            int length = inputLen - offset > maxHandleLength ? maxHandleLength : inputLen - offset;
            cache = cipher.doFinal(data, offset, length);
            out.write(cache, 0, cache.length);
            i++;
            offset = i * maxHandleLength;
        }
        byte[] resultData = out.toByteArray();
        out.close();
        return resultData;
    }

    /**
     * 使用私钥加密数据
     *
     * @param data 需要加密的原文
     * @param key  私钥
     * @return 加密后进行Base64的密文
     */
    public static String encryptByPrivateKey(String data, String key) throws Exception {
        return encryptBASE64(encryptByPrivateKey(data.getBytes(CHARACTER_ENCODING), key));
    }

    /**
     * 使用私钥加密数据
     *
     * @param data 需要加密的数据
     * @param key  私钥
     * @return 加密后的数据
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
        return cryptoByPrivateKey(Cipher.ENCRYPT_MODE, data, decryptBASE64(key));
    }

    /**
     * 使用私钥解密数据
     *
     * @param data 需要解密的密文
     * @param key  私钥
     * @return 解密后的明文
     */
    public static String decryptByPrivateKey(String data, String key) throws Exception {
        return new String(decryptByPrivateKey(decryptBASE64(data), key), CHARACTER_ENCODING);
    }

    /**
     * 使用私钥解密数据
     *
     * @param data 需要解密的数据
     * @param key  私钥
     * @return 解密后的数据
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
        return cryptoByPrivateKey(Cipher.DECRYPT_MODE, data, decryptBASE64(key));
    }

    /**
     * 内部使用，使用私钥加解密数据
     *
     * @param opmode   模式
     * @param data     数据
     * @param keyBytes 密钥的字节数组
     * @return 加解密的结果
     * @throws Exception 加解密失败
     */
    private static byte[] cryptoByPrivateKey(int opmode, byte[] data, byte[] keyBytes) throws Exception {
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据进行加解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(opmode, privateKey);
        return handleResult(opmode, data, cipher);
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       需要签名的数据
     * @param privateKey 私钥
     * @return Base64编码的签名信息
     * @throws Exception 签名失败
     */
    public static String sign(String data, String privateKey) throws Exception {
        return sign(data.getBytes(CHARACTER_ENCODING), privateKey);
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       需要签名的数据
     * @param privateKey 私钥
     * @return Base64编码的签名信息
     * @throws Exception 签名失败
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // 使用Base64解码私钥
        byte[] keyBytes = decryptBASE64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 获取私钥匙对象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 使用私钥对信息生成数字签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);
        return encryptBASE64(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data      被签名的数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return 校验成功返回true，失败返回false
     * @throws Exception 校验错误
     */
    public static boolean verify(String data, String publicKey, String sign) throws Exception {
        return verify(data.getBytes(CHARACTER_ENCODING), publicKey, sign);
    }

    /**
     * 校验数字签名
     *
     * @param data      被签名的数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return 校验成功返回true，失败返回false
     * @throws Exception 校验错误
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        // 使用Base64解码公钥
        byte[] keyBytes = decryptBASE64(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 获取公钥匙对象
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);
        // 验证签名是否正常
        return signature.verify(decryptBASE64(sign));
    }

}
