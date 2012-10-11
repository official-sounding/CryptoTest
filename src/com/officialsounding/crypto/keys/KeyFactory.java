package com.officialsounding.crypto.keys;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.officialsounding.crypto.base.KeyPair;


public class KeyFactory {

	private static KeyFactory instance;
	
	private KeyFactory(){
		
	}
	
	public static KeyFactory getInstance(){
		if(instance == null){
			instance = new KeyFactory();
		}
		
		return instance;
	}
	
	
	public KeyPair<RSAPublicKey,RSAPrivateKey> buildRSAKeyPair(int keysize){
		
		RSAPublicKey pubk;
		RSAPrivateKey privk;
		SecureRandom sr = new SecureRandom();
		
		BigInteger p = BigInteger.probablePrime(keysize/2, sr);
		BigInteger q = BigInteger.probablePrime(keysize/2, sr);
		
		BigInteger n = p.multiply(q);
		BigInteger tot = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		
		BigInteger e = BigInteger.valueOf(0x10001);
		BigInteger d = e.modInverse(tot);
		
		pubk = new RSAPublicKey(n,e);
		privk = new RSAPrivateKey(n,e,d);
		
		return new KeyPair<RSAPublicKey,RSAPrivateKey>(pubk,privk);
	}
}
