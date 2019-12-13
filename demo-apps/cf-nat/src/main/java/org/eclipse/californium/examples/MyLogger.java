package org.eclipse.californium.examples;

import java.util.logging.Level;

public class MyLogger {

	private static void LOG(String msg, Object ...params) {
		
		for(int i = 0 ; i < params.length ; i++) {
			if(params[i] == null) {
				continue;
			}
			
			msg = msg.replaceFirst("\\{\\}", params[i].toString().replace('\\', '_').replace('$', '_'));
		}

		System.out.println(msg);
	}
	
	public static void LOG_info(String msg, Object ...params) {
		LOG(msg, params);
	}
	
	public static void LOG_warn(String msg, Object ...params) {
		LOG(msg, params);
	}
	
	public static void LOG_error(String msg, Object ...params) {
		LOG(msg, params);
	}
	
	public static void LOG_debug(String msg, Object ...params) {
		LOG(msg, params);
	}
	
	public static void LOG_trace(String msg, Object ...params) {
		LOG(msg, params);
	}
	
	public static void LOG_log(String msg, Object ...params) {
		LOG(msg, params);
	}
	
	public static void LOG_log(Level level, String msg, Object ...params) {
		LOG(level + " " + msg, params);
	}
	
	public static boolean isWarnEnabled() {
		return true;
	}
	
	public static boolean isErrorEnabled() {
		return true;
	}
	
	public static boolean isTraceEnabled() {
		return true;
	}
	
	public static boolean isDebugEnabled() {
		return true;
	}
	
	public static boolean isInfoEnabled() {
		return true;
	}
}
