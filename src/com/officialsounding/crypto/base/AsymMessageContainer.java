package com.officialsounding.crypto.base;

public abstract class AsymMessageContainer {

	
	protected byte[] ciphertext;
	
	public AsymMessageContainer(byte[] ciphertext){
		this.ciphertext = ciphertext;
	}
	
	public byte[] getCiphertext(){
		return ciphertext;
	}
}
