package com.officialsounding.crypto.asymmetrical;

public class LamportKey {

	
	protected final byte[][][] key;
	
	
	public LamportKey(byte[][][] key){
		this.key = key;
	}


	
	public byte[][][] getKeyBytes(){
		return key;
	}
}
