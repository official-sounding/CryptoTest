package com.officialsounding.crypto.base;

import com.officialsounding.crypto.util.CryptoContainer;

public interface OperatingModeBase {

	
	public CryptoContainer encrypt(CipherBase cb, byte[] in);
	public byte[] decrypt(CipherBase cb, CryptoContainer in);
}
