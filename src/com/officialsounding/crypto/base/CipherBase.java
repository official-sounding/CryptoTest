package com.officialsounding.crypto.base;

import java.security.InvalidKeyException;

public interface CipherBase {

	public int getBlockSize();
	public void encrypt(byte[] in, int offset) throws IllegalStateException;
	public void decrypt(byte[] in, int offset) throws IllegalStateException;
	public void initialize(byte[] key) throws InvalidKeyException;
	
	public CipherBase getCopy();
}
