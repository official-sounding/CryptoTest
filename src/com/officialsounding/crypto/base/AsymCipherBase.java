package com.officialsounding.crypto.base;

import java.security.InvalidKeyException;

public interface AsymCipherBase {

	
	public AsymMessageContainer encrypt(byte[] message, PublicKey pubk) throws InvalidKeyException;
	public byte[] decrypt(AsymMessageContainer message, PrivateKey privk) throws InvalidKeyException;
}
