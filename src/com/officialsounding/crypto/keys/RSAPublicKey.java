package com.officialsounding.crypto.keys;

import java.math.BigInteger;

import com.officialsounding.crypto.base.PublicKey;

public class RSAPublicKey implements PublicKey {

	BigInteger n;
	BigInteger e;
	
	public RSAPublicKey(BigInteger n, BigInteger e) {
		super();
		this.n = n;
		this.e = e;
	}
	
	public BigInteger getN() {
		return n;
	}
	public BigInteger getE() {
		return e;
	}
	
	public int getKeySizeBytes(){
		return n.bitLength() / 8;
	}
}
