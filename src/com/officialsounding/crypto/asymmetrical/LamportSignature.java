package com.officialsounding.crypto.asymmetrical;

import com.officialsounding.crypto.base.SignatureContainer;

public class LamportSignature implements SignatureContainer {

	private final byte[][] signature;
	
	public LamportSignature(byte[][] signature){
		this.signature = signature;
	}
	
	public byte[][] getSignature(){
		return signature;
	}
}
