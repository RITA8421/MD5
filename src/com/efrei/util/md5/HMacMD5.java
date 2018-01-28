package com.efrei.util.md5;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

public class HMacMD5
{	 
	private final static char[] mChars = "0123456789ABCDEF".toCharArray();
	
	private static byte[] md5(byte[] str) 
			throws NoSuchAlgorithmException
	{
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(str);
		return md.digest();
	}
	
	public static String byte2HexStr(byte[] b, int iLen){  
        StringBuilder sb = new StringBuilder();  
        for (int n=0; n<iLen; n++){  
            sb.append(mChars[(b[n] & 0xFF) >> 4]);  
            sb.append(mChars[b[n] & 0x0F]);  
            //sb.append(' ');  
        }
        //System.out.println(sb.toString().trim().toUpperCase(Locale.US));
        return sb.toString().trim().toUpperCase(Locale.US);  
    }  

/**
* 将待加密数据data，通过密钥key，使用hmac-md5算法进行加密，然后返回加密结果。
* @param key 密钥
* @param data 待加密数据
* @return result of encryption
* @throws NoSuchAlgorithmException
*/
public static byte[] getHmacMd5Bytes(byte[] key,byte[] data) throws NoSuchAlgorithmException
{
/* HmacMd5 calculation formula: H(K XOR opad, H(K XOR ipad, text))
* HmacMd5 计算公式：H(K XOR opad, H(K XOR ipad, text))
* H is MD5 hashing function, K is key, text is the data to encrypt 
* ipad is 0x36，opad is 0x5C。
*/
int length = 64;
byte[] ipad = new byte[length];
byte[] opad = new byte[length];
for(int i = 0; i < 64; i++)
	{
		ipad[i] = 0x36;
		opad[i] = 0x5C;
	}
byte[] actualKey = key; //Actual key.
byte[] keyArr = new byte[length]; //Key bytes of 64 bytes length
/*If key's length is longer than 64,then use hash to digest it and use the result as actual key.
* 如果密钥长度，大于64字节，就使用哈希算法，计算其摘要，作为真正的密钥。
*/
if(key.length>length)
	{
		actualKey = md5(key);
	}
	for(int i = 0; i < actualKey.length; i++)
	{
		keyArr[i] = actualKey[i];
	}
/*append zeros to K
* 如果密钥长度不足64字节，就使用0x00补齐到64字节。
*/
if(actualKey.length < length)
{
for(int i = actualKey.length; i < keyArr.length; i++)
keyArr[i] = 0x00;
}

/*calc K XOR ipad
* 使用密钥和ipad进行异或运算。
*/
byte[] kIpadXorResult = new byte[length];
for(int i = 0; i < length; i++)
{
kIpadXorResult[i] = (byte) (keyArr[i] ^ ipad[i]);
}

/*append "text" to the end of "K XOR ipad"
* 将待加密数据追加到K XOR ipad计算结果后面。
*/
byte[] firstAppendResult = new byte[kIpadXorResult.length+data.length];
	for(int i=0;i<kIpadXorResult.length;i++)
	{
		firstAppendResult[i] = kIpadXorResult[i];
		}
	for(int i=0;i<data.length;i++)
	{
		firstAppendResult[i+keyArr.length] = data[i];
		}

/*calc H(K XOR ipad, text)
* 使用哈希算法计算上面结果的摘要。
*/
byte[] firstHashResult = md5(firstAppendResult);

/*calc K XOR opad
* 使用密钥和opad进行异或运算。
*/
	byte[] kOpadXorResult = new byte[length];
	for(int i = 0; i < length; i++)
	{
		kOpadXorResult[i] = (byte) (keyArr[i] ^ opad[i]);
		}

/*append "H(K XOR ipad, text)" to the end of "K XOR opad"
* 将H(K XOR ipad, text)结果追加到K XOR opad结果后面
*/ 
	byte[] secondAppendResult = new byte[kOpadXorResult.length+firstHashResult.length];
	for(int i=0;i<kOpadXorResult.length;i++)
	{
		secondAppendResult[i] = kOpadXorResult[i];
		}
	for(int i=0;i<firstHashResult.length;i++)
	{
		secondAppendResult[i+keyArr.length] = firstHashResult[i];
		}

/*H(K XOR opad, H(K XOR ipad, text))
* 对上面的数据进行哈希运算。
*/
	byte[] hmacMd5Bytes = md5(secondAppendResult);
	//System.out.println(hmacMd5Bytes);
	System.out.println("HMAC encryption: " + byte2HexStr(hmacMd5Bytes,16));
	return hmacMd5Bytes;
	}
}
