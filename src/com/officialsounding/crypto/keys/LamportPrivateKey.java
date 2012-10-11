package com.officialsounding.crypto.keys;

import java.security.SecureRandom;

import com.officialsounding.crypto.asymmetrical.LamportKey;
import com.officialsounding.crypto.base.PrivateKey;

public class LamportPrivateKey extends LamportKey implements PrivateKey {

	
	public LamportPrivateKey(){
		super(generateKeyBytes());
	}
	
	public static PrivateKey generateKey(){
		return new LamportPrivateKey();
	}
	
	private static byte[][][] generateKeyBytes() {
		byte[][][] pk = new byte[256][2][32];
		SecureRandom sr = new SecureRandom();
		
		for(int i = 0; i < 256; i++){
			for(int j = 0; j < 2; j++){
				sr.nextBytes(pk[i][j]);
			}
		}
		
		return pk;
	}
}
