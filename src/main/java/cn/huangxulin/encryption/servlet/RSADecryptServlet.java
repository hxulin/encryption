package cn.huangxulin.encryption.servlet;

import cn.huangxulin.encryption.utils.RSAUtils;
import com.alibaba.fastjson.JSONObject;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 功能描述: RSA 解密接口
 *
 * @author hxulin
 */
public class RSADecryptServlet extends HttpServlet {

	private static final long serialVersionUID = 8524218191075165945L;

	@Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
        resp.setContentType("text/html;charset=utf-8");
        JSONObject jsonObject = new JSONObject();
        try {
            // 获取加密数据
            String cipherText = req.getParameter("cipherText");
            // 从 session 中获取私钥
            String privateKey = (String) req.getSession().getAttribute("private_key_in_session");
            if (privateKey != null) {
                String decrypt = RSAUtils.decryptByPrivateKey(cipherText, privateKey);
                jsonObject.put("decrypt", decrypt);
                resp.getWriter().println(jsonObject.toJSONString());
                return;
            }
            throw new RuntimeException("SESSION EXPIRATION");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
