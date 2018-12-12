package cn.huangxulin.encryption;

import cn.huangxulin.encryption.servlet.RSADecryptServlet;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.WebAppContext;

import cn.huangxulin.encryption.servlet.CryptoServlet;

/**
 * 程序入口
 *
 * @author hxulin
 */
public class Application {
	
	/**
	 * 服务器端口
	 */
	private static final int SERVER_PORT = 80;

	/**
	 * 上下文路径
	 */
	private static final String CONTEXT_PATH = "";

	public static void main(String[] args) throws Exception {
		WebAppContext context = new WebAppContext();
		context.setResourceBase("webapp");
		context.setContextPath(CONTEXT_PATH);

		// 添加 Servlet
		context.addServlet(CryptoServlet.class, "/crypto");
		context.addServlet(RSADecryptServlet.class, "/rsaDecrypt");

		// 创建并启动内置 Jetty 服务器
		Server server = new Server(SERVER_PORT);
		server.setStopAtShutdown(true);
		server.setHandler(context);
		System.out.println("========== 启动 Jetty 服务器 ==========");
		System.out.println("Port: " + SERVER_PORT);
		System.out.println("ContextPath: " + CONTEXT_PATH);
		System.out.println("Host: http://localhost:"+ SERVER_PORT + CONTEXT_PATH);
		System.out.println("====================================");
		server.start();
		server.join();
	}
}
