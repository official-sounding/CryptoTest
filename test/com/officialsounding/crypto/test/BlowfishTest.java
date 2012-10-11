package com.officialsounding.crypto.test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import com.officialsounding.crypto.cipher.Blowfish;
import com.officialsounding.crypto.util.Util;

public class BlowfishTest {

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testVector1() throws InvalidKeyException {
		byte[] key = new byte[8];
		byte[] pt  = new byte[8];
		byte[] ct  = new BigInteger("4EF997456198DD78",16).toByteArray();
		
		Blowfish bf = new Blowfish();
		bf.initialize(key);
		bf.encrypt(pt, 0);
		assertTrue("encrypt failed:"+Util.toHex(pt),Arrays.equals(pt, ct));
		bf.decrypt(pt, 0);
		assertTrue("decrypt failed:"+Util.toHex(pt),Arrays.equals(pt, new byte[8]));
	}
	
	@Test
	public void testVector2() throws InvalidKeyException {
		byte[] key = new byte[8];
		byte[] pt  = new byte[8];
		byte[] res = new byte[8];
		byte[] ct  = new BigInteger("51866FD5B85ECB8A",16).toByteArray();

		Arrays.fill(key, (byte) 0xff);
		Arrays.fill(pt , (byte) 0xff);
		Arrays.fill(res, (byte) 0xff);
		
		Blowfish bf = new Blowfish();
		bf.initialize(key);
		bf.encrypt(pt, 0);
		assertTrue("encrypt failed:"+Util.toHex(pt),Arrays.equals(pt, ct));
		bf.decrypt(pt, 0);
		assertTrue("decrypt failed:"+Util.toHex(pt),Arrays.equals(pt, res));
	}
}
