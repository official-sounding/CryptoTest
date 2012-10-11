package com.officialsounding.crypto.asymmetrical;

import java.math.BigInteger;

import com.officialsounding.crypto.base.SignatureContainer;

public class RSASignature implements SignatureContainer {

	private final BigInteger signature;
	
	public RSASignature(BigInteger signature){
		this.signature = signature;
	}
	
	public BigInteger getSignature(){
		return signature;
	}
}
