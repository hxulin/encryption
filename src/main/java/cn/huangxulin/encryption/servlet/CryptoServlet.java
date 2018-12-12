package cn.huangxulin.encryption.servlet;

import cn.huangxulin.encryption.utils.AESUtils;
import cn.huangxulin.encryption.utils.RSAUtils;
import com.alibaba.fastjson.JSONObject;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.KeyPair;

/**
 * 功能描述: 初始化加解密接口
 *
 * @author hxulin
 */
public class CryptoServlet extends HttpServlet {

    private static final long serialVersionUID = 1687904033604900658L;

    private static final String AES_SRC_DATA = "春江潮水连海平，海上明月共潮生。";

    private static final String RSA_SRC_DATA = "白云一片去悠悠，青枫浦上不胜愁。";

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
        resp.setContentType("text/html;charset=utf-8");
        JSONObject jsonObject = new JSONObject();

        // 初始化 AES 算法的密钥
        String aesKey = AESUtils.initKey();
        String aesIV = AESUtils.initIV();
        jsonObject.put("aesKey", aesKey);
        jsonObject.put("aesIV", aesIV);
        jsonObject.put("aesSrcData", AES_SRC_DATA);

        // 初始化 RSA 算法的密钥
        KeyPair keyPair = RSAUtils.initKey();
        String rsaPublicKey = RSAUtils.getPublicKey(keyPair);
        String rsaPrivateKey = RSAUtils.getPrivateKey(keyPair);
        jsonObject.put("rsaPublicKey", rsaPublicKey);
        jsonObject.put("rsaPrivateKey", rsaPrivateKey);
        jsonObject.put("rsaSrcData", RSA_SRC_DATA);

        // 将私钥存放到 Session 中
        req.getSession().setAttribute("private_key_in_session", rsaPrivateKey);

        try {
            // AES 加密和解密
            String aesEncrypt = AESUtils.encrypt(AES_SRC_DATA, aesKey, aesIV);
            String aesDecrypt = AESUtils.decrypt(aesEncrypt, aesKey, aesIV);
            jsonObject.put("aesEncrypt", aesEncrypt);
            jsonObject.put("aesDecrypt", aesDecrypt);

            // RSA 加密解密数据
            String rsaEncrypt = RSAUtils.encryptByPublicKey(RSA_SRC_DATA, rsaPublicKey);
            String rsaDecrypt = RSAUtils.decryptByPrivateKey(rsaEncrypt, rsaPrivateKey);
            jsonObject.put("rsaEncrypt", rsaEncrypt);
            jsonObject.put("rsaDecrypt", rsaDecrypt);

            resp.getWriter().println(jsonObject.toJSONString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
