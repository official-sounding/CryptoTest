package com.officialsounding.crypto.test;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import com.officialsounding.crypto.hash.HMAC;

public class HMACTest {

	HMAC hmac = new HMAC();
	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testHMACdigestStringString() {
		String output = hmac.digest("", "");
		assertTrue(output,output.equals("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"));
	}

	@Test
	public void testHMACdigestByteArrayByteArray() {
		byte[] output = hmac.digest(new byte[0], new byte[0]);
		assertTrue(Arrays.toString(output)+output[1],output[1] == (byte)0x13);
	}

}
