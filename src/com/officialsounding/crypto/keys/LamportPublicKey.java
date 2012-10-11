package com.officialsounding.crypto.keys;

import com.officialsounding.crypto.asymmetrical.LamportKey;
import com.officialsounding.crypto.base.PublicKey;
import com.officialsounding.crypto.hash.SHA256;

public class LamportPublicKey extends LamportKey implements PublicKey{

	public LamportPublicKey(byte[][][] key) {
		super(key);
		// TODO Auto-generated constructor stub
	}
	
	public LamportPublicKey(LamportPrivateKey privkey){
		super(generateFromPrivate(privkey));
	}

	private static byte[][][] generateFromPrivate(LamportPrivateKey pk) {
		byte[][][] pubkey = new byte[256][2][32];
		byte[][][] privkey = pk.getKeyBytes();
		SHA256 hash = new SHA256();
		
		for(int i = 0; i < 256; i++){
			for(int j = 0; j < 2; j++){
				pubkey[i][j] = hash.digest(privkey[i][j]);
			}
		}
		
		return pubkey;
	}
	
	
}
