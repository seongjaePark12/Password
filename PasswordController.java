package com.spring.javagreenS;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/password")
public class PasswordController {
	@Autowired
	BCryptPasswordEncoder passwordEncoder;
  
  @RequestMapping(value = "/password/passCheck1", method = RequestMethod.GET)
	public String passCheck1Get() {
		return "password/passCheck1";
	}
	
	@RequestMapping(value = "/password/passCheck1", method = RequestMethod.POST)
	public String passCheck1Post(long pwd, Model model) {
		// 암호화를 위한 키 : 0x1234ABCD
		long key = 0x1234ABCD;
		long encPwd, decPwd;
		
		encPwd = pwd ^ key;    // 암호화 : DB에 저장시켜준다.
		
		decPwd = encPwd ^ key;    // 복호화
		
		model.addAttribute("pwd", pwd);
		model.addAttribute("encPwd", encPwd);
		model.addAttribute("decPwd", decPwd);
		
		return "../passCheck1";
	}
	
	@RequestMapping(value = "/password/passCheck2", method = RequestMethod.POST)
	public String passCheck2Post(String pwd, Model model) {
		// 입력문자가 영문 소문자일경우는 대문자로 변경처리(연산시에 자리수 Over 때문에...)
		pwd = pwd.toUpperCase();
		
		// 입력된 비밀번호를 아스키코드로 변환하여 누적처리
		long intPwd;
		String strPwd = "";
		for(int i=0; i<pwd.length(); i++) {
			intPwd = (long) pwd.charAt(i);
			strPwd += intPwd;
		}
		// 문자로 결합된 숫자를, 연산하기위해 다시 숫자로 변환한다.
		intPwd = Long.parseLong(strPwd);
		
		// 암호화를 위한 키 : 0x1234ABCD
		long key = 0x1234ABCD;
		long encPwd, decPwd;
		
		// 암호화를 위한 EOR 연산하기
		encPwd = intPwd ^ key;
		strPwd = String.valueOf(encPwd);  // 암호화 : DB에 저장시켜준다.
		model.addAttribute("encPwd", strPwd);	// 암호화된 문자...
		
		// 복호화 작업처리
		intPwd = Long.parseLong(strPwd);
		decPwd = intPwd ^ key;
		strPwd = String.valueOf(decPwd);
		
		// 복호화된 문자형식의 아스키코드값을 2개씩 분류하여 실제문자로 변환해준다.
		String result = "";
		char ch;
		
		for(int i=0; i<strPwd.length(); i+=2) {
			ch = (char) Integer.parseInt(strPwd.substring(i, i+2));
			result += ch;
		}
		model.addAttribute("decPwd", result);
		model.addAttribute("pwd", pwd);
		return "../passCheck1";
	}
  	// aria 암호화 방식연습
	@RequestMapping(value = "/password3/aria", method = RequestMethod.GET)
	public String ariaGet() {
		return "../aria";
	}
	
	@ResponseBody
	@RequestMapping(value = "/password3/aria", method = RequestMethod.POST)
	public String ariaPost(String pwd) {
		String encPwd = "";
		String decPwd = "";
		
		try {
			encPwd = ARIAUtil.ariaEncrypt(pwd);
			decPwd = ARIAUtil.ariaDecrypt(encPwd);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		pwd = "Encoding : " + encPwd + " / Decoding : " + decPwd;
		
		return pwd;
	}
  
	
  // BCryptPasswordEncoder 암호화 방식연습
	@RequestMapping(value = "/password3/securityCheck", method = RequestMethod.GET)
	public String securityCheckGet() {
		return "../security";
	}
	
	@ResponseBody
	@RequestMapping(value = "/password3/securityCheck", method = RequestMethod.POST)
	public String securityCheckPost(String pwd) {
		String encPwd = "";
		
		encPwd = passwordEncoder.encode(pwd);
		
		pwd = "Encoding : " + encPwd + " / Source Password : " + pwd;
		
		return pwd;
	}
}
