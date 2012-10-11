package com.officialsounding.crypto.hash;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import com.officialsounding.crypto.hash.SHA256;
import com.officialsounding.crypto.util.Util;

public class HMAC {

	
	private final int BLOCKSIZE;
	private SHA256 sha;
	private static final String encoding = "US-ASCII";
	
	public HMAC(){
		sha = new SHA256();
		BLOCKSIZE = 64;
	}
	
	/**
	 * Create an HMAC-SHA256 signature based on a ASCII Key and message
	 * @param key a string representing the key of an arbitrary length
	 * @param message a string representing the message of arbitrary length
	 * @return
	 */
	public String digest(String key, String message){
		
		byte[] output = null;
		
		try {
			output = digest(key.getBytes(encoding),message.getBytes(encoding));
		} catch (UnsupportedEncodingException ignored) {	}
		
		
		return Util.toHex(output);
	}
	
	/**
	 * Create an HMAC-SHA256 signature based on a byte array message
	 * @param key a byte array representing the key of an arbitrary length
	 * @param message
	 * @return
	 */
	public byte[] digest(byte[] key, byte[] message){
		
		byte[] i_pad = new byte[BLOCKSIZE];
		byte[] o_pad = new byte[BLOCKSIZE];
	
		byte[] intermediatedigest;
		
		Arrays.fill(i_pad, (byte)0x36);
		Arrays.fill(o_pad, (byte)0x5c);
		
		if(key.length > BLOCKSIZE){
			key = sha.digest(key);
		}else if(key.length < BLOCKSIZE){
			key = Arrays.copyOf(key, BLOCKSIZE);
		}
		
		//o_key_pad = o_pad ^ key
		Util.xorArray(o_pad, key);
		Util.xorArray(i_pad, key);
		
		//intermediate = hash(i_key_pad || message)
		intermediatedigest = sha.digest(Util.concatArray(i_pad,message));
		
		//final value = hash(o_key_pad || intermediate)
		return sha.digest(Util.concatArray(o_pad,intermediatedigest));
	}

	


}

