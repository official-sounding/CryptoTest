package com.officialsounding.crypto.base;

import java.security.InvalidKeyException;

public interface SigningBase {

	public boolean verify(PublicKey pubk, byte[] message, SignatureContainer signature);
	public SignatureContainer sign(PrivateKey privk, byte[] message) throws InvalidKeyException;
}
