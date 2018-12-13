package cn.huangxulin.encryption.utils;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加解密的工具类
 *
 * @author hxulin
 */
public final class AESUtils {

    /**
     * 字符编码
     */
    private static final String CHARACTER_ENCODING = "utf-8";

    /**
     * 生成密钥的基本字符
     */
    private static final String BASE_CHARACTER = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private AESUtils() {

    }

    /**
     * 生成随机密钥
     *
     * @return 随机密钥
     */
    public static String initKey() {
        return generateKeyOrIV();
    }

    /**
     * 生成初始向量
     *
     * @return 初始向量
     */
    public static String initIV() {
        return generateKeyOrIV();
    }

    /**
     * 生成随机密钥、初始向量
     */
    private static String generateKeyOrIV() {
        StringBuilder sBuilder = new StringBuilder();
        double r;
        for (int i = 0; i < 16; i++) {
            r = Math.random() * BASE_CHARACTER.length();
            sBuilder.append(BASE_CHARACTER.charAt((int) r));
        }
        return sBuilder.toString();
    }

    /**
     * 使用AES算法加密字符串
     *
     * @param data 需要加密的原文
     * @param key  密钥(16位字母、数字或符号)
     * @param iv   初始向量(16位字母、数字或符号)，使用CBC模式，需要一个向量iv，可增加加密算法的强度
     * @return 加密后进行Base64的密文
     * @throws Exception 加密失败
     */
    public static String encrypt(String data, String key, String iv) throws Exception {
        return Base64.getEncoder().encodeToString(encrypt(data.getBytes(CHARACTER_ENCODING), key, iv));
    }

    /**
     * 使用AES算法加密数据
     *
     * @param data 需要加密的数据
     * @param key  密钥(16位字母、数字或符号)
     * @param iv   初始向量(16位字母、数字或符号)，使用CBC模式，需要一个向量iv，可增加加密算法的强度
     * @return 加密后的数据
     * @throws Exception 加密失败
     */
    public static byte[] encrypt(byte[] data, String key, String iv) throws Exception {
        return crypto(Cipher.ENCRYPT_MODE, data, key, iv);
    }

    /**
     * 使用AES算法解密字符串
     *
     * @param data 需要解密的密文
     * @param key  密钥(16位字母、数字或符号)
     * @param iv   初始向量(16位字母、数字或符号)
     * @return 解密后的明文
     * @throws Exception 解密失败
     */
    public static String decrypt(String data, String key, String iv) throws Exception {
        byte[] decrypted = decrypt(Base64.getDecoder().decode(data), key, iv);
        return new String(decrypted, CHARACTER_ENCODING);
    }

    /**
     * 使用AES算法解密数据
     *
     * @param data 需要解密的数据
     * @param key  密钥(16位字母、数字或符号)
     * @param iv   初始向量(16位字母、数字或符号)
     * @return 解密后的数据
     * @throws Exception 解密失败
     */
    public static byte[] decrypt(byte[] data, String key, String iv) throws Exception {
        return crypto(Cipher.DECRYPT_MODE, data, key, iv);
    }

    /**
     * 加解密数据
     */
    private static byte[] crypto(int opmode, byte[] content, String key, String iv) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(CHARACTER_ENCODING), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  // 算法/模式/补码方式
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(CHARACTER_ENCODING));
        cipher.init(opmode, keySpec, ivParameterSpec);
        return cipher.doFinal(content);
    }

}