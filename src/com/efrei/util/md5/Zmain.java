package com.efrei.util.md5;

import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Random;
import com.efrei.util.md5.*;
import com.sun.corba.se.impl.oa.poa.ActiveObjectMap.Key;

public class Zmain {
		//生成随机密码
		//Generate a random password
		public static String genRandomNum(int pwd_len) {  
		//35是因为数组是从0开始的，26个字母+10个数字
		//Start from 0, 26 letters + 10 numbers
		final int maxNum = 36;  
		int i; //生成的随机数 Random number 
		int count = 0; //生成的密码的长度 The length of the password  
		char[] str = { 'a','b','c','d','e','f','g','h','i','j','k','l','m',
				       'n','o','p','q','r','s','t','u','v','w','x','y','z',
				       '0','1','2','3','4','5','6','7','8','9'};  
		StringBuffer pwd = new StringBuffer("");  
		Random r = new Random();
			while (count < pwd_len) {  
				//生成随机数，取绝对值，防止生成负数
				//Generate a random number, take the absolute value, prevent the generation of negative numbers
				i = Math.abs(r.nextInt(maxNum)); //生成的数最大为36-1 the biggest generated number is 36-1 
				if (i >= 0 && i < str.length) {  
					pwd.append(str[i]);  
					count++;  
				}  
			}  
		return pwd.toString();  
		}  

	//Main
	public static void main(String args[]) throws NoSuchAlgorithmException {
		Storage storage = new Storage();
			for(int id=1; id<=100; id++) 
			{
				int pl;
				Random i = new Random();
				pl = Math.abs(i.nextInt(20))+1;
				String plaintext = genRandomNum(pl);
				System.out.println(" id"+id + " password：" + plaintext);
				storage.setMap(id, MD5Util.MD5(plaintext));
				storage.getMap();
			}
			System.out.println("pwd after MD5："+storage.getMap());
		
		//获取加盐后的MD5值
		//MD5 with salt
		Storage storage2 = new Storage();
		for(int id=1; id<=100; id++) {
		int pl;
		Random i = new Random();
		pl = Math.abs(i.nextInt(20))+1;
		String plaintext = genRandomNum(pl);
		storage2.setMap(id, MD5Util.generate(plaintext));
		storage2.getMap();
		}
			System.out.println("MD5 encryption with salt："+storage2.getMap());		
		
		//HMAC
		System.out.println("HMAC encryption: ");
		int length = 64;
		byte[]  n= new byte[length];
		for(int i = 0; i < 16; i++)
			{
				n[i] = 0x36;
			}
		HMacMD5 hMacMD5 = new HMacMD5();
		System.out.println("key is: " + hMacMD5.byte2HexStr(n,16));
		System.out.println("data is: " + hMacMD5.byte2HexStr(n,16));
		HMacMD5.getHmacMd5Bytes(n, n);
		
//		int size = 64;   
//		byte[] byt = new byte[size];   
//		for(int i=0;i<size;i++){   
//			    byt[i]=1;   
//		}
//		byte[] byt2 = new byte[size];   
//		for(int i=0;i<size;i++){   
//			byt[i]=1;   
//		}
//		System.out.println(byt2);
//		System.out.println(byt);
//		for(int i=0;i<11;i++){   
//			System.out.println((int)HMacMD5.getHmacMd5Bytes(byt, byt2)[i]);  
//		}  
	}
}
