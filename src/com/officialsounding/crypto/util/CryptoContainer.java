package com.officialsounding.crypto.util;

public class CryptoContainer {

	private final byte[] IV;
	private final byte[] ct;
	private final CryptoDefinition cd;
	
	public CryptoContainer(byte[] ct, byte[] iv, CryptoDefinition cd) {
		this.IV = iv;
		this.ct = ct;
		this.cd = cd;
	}

	public byte[] getIV() {
		return IV;
	}

	public byte[] getCt() {
		return ct;
	}

	public CryptoDefinition getCd() {
		return cd;
	}
	
	
	
	
}
