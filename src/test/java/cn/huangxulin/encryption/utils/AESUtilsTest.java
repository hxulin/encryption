package cn.huangxulin.encryption.utils;

import org.junit.Before;
import org.junit.Test;

/**
 * AES加解密测试
 *
 * @author hxulin
 */
public class AESUtilsTest {

	private String key;

	private String iv;

	@Before
	public void init() {
		System.out.println("------------------------------------");
		key = AESUtils.initKey();
		System.out.println("生成密钥：" + key);
		iv = AESUtils.initIV();
		System.out.println("生成初始向量：" + iv);
		System.out.println("------------------------------------");
	}

	@Test
	public void test() throws Exception {

//		String key = "7W1evRIk1zAxiPsn";  // 密钥
//    	String iv = "6og1Mh5ZtCRnUY61";  // 初始向量

    	String content = "你好师姐";
    	String encrypt = AESUtils.encrypt(content, key, iv);
        System.out.println("明文内容："+ content);  // 我爱你
        System.out.println("明文长度："+ content.length());
        System.out.println("加密结果："+ encrypt);  // SUgTkCjpkLBlspbKcsV9Fg==
        System.out.println("密文长度："+ encrypt.length());
        System.out.println("解密结果："+ AESUtils.decrypt(encrypt, key, iv));  // 我爱你

        
        // 计算该算法加密后的密文长度
        System.out.println("------------------------------------");
        System.out.println("加密长度计算:");
        
    	int len = 300;  // 设置需要加密的字符长度
    	
    	String letter = "E";			// 英文字符或数字, 加密前后长度: 300 -> 408
    	String chineseChar = "中";		// 汉字, 加密前后长度: 300 -> 1216
    	StringBuilder letterBuilder = new StringBuilder(len);
    	StringBuilder charBuilder = new StringBuilder(len);
    	for (int i = 0; i < len; i++) {
    		letterBuilder.append(letter);
    		charBuilder.append(chineseChar);
    	}
    	System.out.println(len + "个英文字符或数字, 加密后长度为: " + AESUtils.encrypt(letterBuilder.toString(), key, iv).length());
    	System.out.println(len + "个汉字, 加密后长度为: " + AESUtils.encrypt(charBuilder.toString(), key, iv).length());
	}

}
