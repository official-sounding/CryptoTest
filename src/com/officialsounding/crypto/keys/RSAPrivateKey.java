package com.officialsounding.crypto.keys;

import java.math.BigInteger;

import com.officialsounding.crypto.base.PrivateKey;

public class RSAPrivateKey implements PrivateKey {
	
	private final BigInteger n;
	private final BigInteger e;
	private final BigInteger d;
	
	
	public RSAPrivateKey(BigInteger n, BigInteger e, BigInteger d) {
		super();
		this.n = n;
		this.e = e;
		this.d = d;
	}
	public BigInteger getN() {
		return n;
	}
	public BigInteger getE() {
		return e;
	}
	public BigInteger getD() {
		return d;
	}
	
	public int getKeySizeBytes(){
		return n.bitLength() / 8;
	}
}
