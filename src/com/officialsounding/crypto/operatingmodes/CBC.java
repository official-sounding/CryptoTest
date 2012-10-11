package com.officialsounding.crypto.operatingmodes;

import java.security.SecureRandom;

import com.officialsounding.crypto.base.*;
import com.officialsounding.crypto.util.*;

public class CBC implements OperatingModeBase {

	public CryptoContainer encrypt(CipherBase cb, byte[] in) {
		//check input
		
		int blocksize = cb.getBlockSize();
		int i = blocksize;
		// generate IV
		SecureRandom sr = new SecureRandom();
		byte[] iv = new byte[blocksize];
		sr.nextBytes(iv);
		
		// encrypt blocks
		byte[] ct = Util.concatArray(iv, in);
		for(; i < ct.length - (ct.length % blocksize); i += blocksize){
			//xor with previous pt block (pt0 is IV)
			Util.xorArray(ct, ct, i, i-blocksize, blocksize);
			//encrypt block
			cb.encrypt(ct, i);
		}
		
		// residual block termination for final block
		Util.residualBlockTerminationEncrypt(cb, blocksize, i, ct);
		// return ciphertext object
		return new CryptoContainer(ct,iv,new CryptoDefinition(cb.getCopy(),this));
		
	}

	public byte[] decrypt(CipherBase cb, CryptoContainer in) {
		// TODO Auto-generated method stub
		return null;
	}

}
