package com.officialsounding.crypto.test;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import com.officialsounding.crypto.asymmetrical.*;
import com.officialsounding.crypto.base.AsymMessageContainer;
import com.officialsounding.crypto.base.KeyPair;
import com.officialsounding.crypto.base.SignatureContainer;
import com.officialsounding.crypto.keys.KeyFactory;
import com.officialsounding.crypto.keys.RSAPrivateKey;
import com.officialsounding.crypto.keys.RSAPublicKey;

public class RSATest extends RSA{

	
	byte[] input;
	
	@Before
	public void setUp() throws Exception {
		input = "aaabbbccc".getBytes("US-ASCII");
	}

	@Test
	public void testSign() throws InvalidKeyException {
		KeyPair<RSAPublicKey,RSAPrivateKey> kp = KeyFactory.getInstance().buildRSAKeyPair(2048);
		
		SignatureContainer signature = sign(kp.getPrivateKey(),input);
		assertTrue(verify(kp.getPublicKey(),input,signature));
	}

	//@Test
	public void testEncrypt() throws InvalidKeyException {
		KeyPair<RSAPublicKey,RSAPrivateKey> kp = KeyFactory.getInstance().buildRSAKeyPair(2048);
		for(int i = 0; i < 10; i++){
		AsymMessageContainer encryptedmessage = encrypt(input,kp.getPublicKey());
		byte[] output = decrypt(encryptedmessage,kp.getPrivateKey());
		
		assertTrue("failed on index "+i+Arrays.toString(output),Arrays.equals(input, output));
		}
	}

	//@Test
	public void testOAEP() throws UnsupportedEncodingException {
		
		byte[] paddedmessage = OAEPPad(256, input, "".getBytes());
		byte[] outputbytes = OAEPUnpad(paddedmessage);
		String output = new String(outputbytes,"US-ASCII");
		
		assertTrue(paddedmessage.length+"",paddedmessage.length == 256);
		assertTrue(output,output.equals("aaabbbccc"));
	}
}
