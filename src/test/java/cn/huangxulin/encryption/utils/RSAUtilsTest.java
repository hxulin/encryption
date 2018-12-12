package cn.huangxulin.encryption.utils;

import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;

/**
 * RSA加解密测试
 *
 * @author hxulin
 */
public class RSAUtilsTest {

	private String publicKey;
	private String privateKey;

	@Before
	public void init() {
		System.out.println("------------------------------------------------");
		// 初始化RSA密钥对
		KeyPair keyPair = RSAUtils.initKey();
		// 获取公钥
		publicKey = RSAUtils.getPublicKey(keyPair);
		System.out.println("生成公钥：" + publicKey);
		// 获取私钥
		privateKey = RSAUtils.getPrivateKey(keyPair);
		System.out.println("生成私钥：" + privateKey);
		System.out.println("------------------------------------------------");
	}

	@Test
	public void test() throws Exception {
		String data = "欢迎访问 https://huangxulin.cn/";
		System.out.println("待加密数据：" + data);
		System.out.println();

		String encrypt = RSAUtils.encryptByPublicKey(data, publicKey);
		System.out.println("公钥加密：" + encrypt);
		String decrypt = RSAUtils.decryptByPrivateKey(encrypt, privateKey);
		System.out.println("私钥解密：" + decrypt);
		System.out.println();

		encrypt = RSAUtils.encryptByPrivateKey(data, privateKey);
		System.out.println("私钥加密：" + encrypt);
		decrypt = RSAUtils.decryptByPublicKey(encrypt, publicKey);
		System.out.println("公钥解密：" + decrypt);
		System.out.println();

		String sign = RSAUtils.sign(data, privateKey);
		System.out.println("私钥签名：" + sign);
		boolean verify = RSAUtils.verify(data, publicKey, sign);
		System.out.println("公钥验签：" + verify);
	}

}
