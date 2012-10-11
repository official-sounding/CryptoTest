package com.officialsounding.crypto.test;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import com.officialsounding.crypto.hash.SHA256;

public class SHA256Test {

	SHA256 sha;
	@Before
	public void setUp() throws Exception {
		sha = new SHA256();
	}

	@Test
	public void testDigestZeroLength() {
		byte[] output = sha.digest(new byte[0]);
		assertTrue(Arrays.toString(output),output[0] == (byte) 0xe3);
		assertTrue(Arrays.toString(output),output[output.length-1] == (byte) 0x55);
	}
	
	@Test
	public void testDigest() throws UnsupportedEncodingException{
		byte[] input = "abc".getBytes("US-ASCII");
		byte[] output = sha.digest(input);
		assertTrue(Arrays.toString(output),output[0] == (byte) 0xba);
	}

}
