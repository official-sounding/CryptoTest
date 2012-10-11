package com.officialsounding.crypto.operatingmodes;

import com.officialsounding.crypto.base.*;
import com.officialsounding.crypto.util.*;

public class ECB implements OperatingModeBase{

	public CryptoContainer encrypt(CipherBase cb, byte[] in) {
		//check input
		
		int blocksize = cb.getBlockSize();
		int i = blocksize;

		for(; i < in.length - (in.length % blocksize); i += blocksize){
			//xor with previous pt block (pt0 is IV)
			
			//encrypt block
			cb.encrypt(in, i);
		}
		
		// residual block termination for final block
		Util.residualBlockTerminationEncrypt(cb, blocksize, i, in);
		// return ciphertext object
		return new CryptoContainer(in,null,new CryptoDefinition(cb.getCopy(),this));
	}

	public byte[] decrypt(CipherBase cb, CryptoContainer in) {
		// TODO Auto-generated method stub
		return null;
	}

}
