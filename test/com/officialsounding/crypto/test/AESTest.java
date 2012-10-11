package com.officialsounding.crypto.test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import com.officialsounding.crypto.cipher.AES;
import com.officialsounding.crypto.util.GF256;
import com.officialsounding.crypto.util.Util;

public class AESTest extends AES{

	byte[] pt_orig = 
	{	  0x00,		 0x11,		0x22,      0x33,
		  0x44,		 0x55,		0x66,	   0x77,
	(byte)0x88,(byte)0x99,(byte)0xaa,(byte)0xbb,
	(byte)0xcc,(byte)0xdd,(byte)0xee,(byte)0xff};
	
	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testEncrypt() throws InvalidKeyException {
		byte[] key = new BigInteger("2b7e151628aed2a6abf7158809cf4f3c",16).toByteArray();
		byte[] pt = new BigInteger("3243f6a8885a308d313198a2e0370734",16).toByteArray();
		byte[] ct =  new BigInteger("3925841d02dc09fbdc118597196a0b32",16).toByteArray();
		initialize(key);
		encrypt(pt,0);
		assertTrue(Util.toHex(pt),Arrays.equals(ct, pt));
	}

	@Test
	public void testInitialize128bitkey() throws InvalidKeyException {
		byte[] key = new BigInteger("2b7e151628aed2a6abf7158809cf4f3c",16).toByteArray();
		initialize(key);
		assertTrue("0: "+expandedkey[0],expandedkey[0]==0x2b);
		assertTrue("16: "+(byte)expandedkey[16],expandedkey[16]==(byte)0xa0);
	}
	
	@Test
	public void testInitialize256bitkey() throws InvalidKeyException {
		byte[] key = new BigInteger("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",16).toByteArray();
		initialize(key);

		assertTrue("0: "+expandedkey[0],expandedkey[0]==0x60);
		assertTrue("16: "+(byte)expandedkey[32],expandedkey[32]==(byte)0x9b);
		assertTrue("84: "+(byte)expandedkey[84],expandedkey[84]==(byte)0x26);
	}

	@Test
	public void testShiftRows(){
		byte[] input = {0,1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF};
		shiftRows(input);
		assertTrue(input[0] == 0);
		assertTrue(""+input[15],input[15]== 0xE);
		assertTrue(""+input[4],input[4]== 0x5);
	}
	@Test
	public void testGF256() {
		byte multresult = GF256.mult((byte)0xca,(byte)0x53);
		byte invresult = GF256.inv((byte) 0xca);
		assertTrue("Multiply failure "+multresult,multresult==(byte)0x01);
		assertTrue("Inverse failure "+invresult,invresult==(byte)0x53);
	}

	@Test
	public void testLR() {
		byte[] input    = {0x01, 0x23, 0x45, 0x67};
		byte[] result8  = {0x23, 0x45, 0x67, 0x01};
		byte[] result16 = {0x45, 0x67, 0x01, 0x23};
		
		byte[] output8  = Arrays.copyOf(input, input.length);
		byte[] output16 = Arrays.copyOf(input, input.length);
		Util.lr(output8 ,  8);
		Util.lr(output16, 16);
		assertTrue("8  bit shift failed: "+Arrays.toString(output8),Arrays.equals(output8, result8));
		assertTrue("16 bit shift failed: "+Arrays.toString(output16),Arrays.equals(output16, result16));
	}

	@Test
	public void testVector128() throws InvalidKeyException {
	
		byte[] key =
			{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			 0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
		byte[] pt = Arrays.copyOf(pt_orig, pt_orig.length);

		byte[] ct =  new BigInteger("69c4e0d86a7b0430d8cdb78070b4c55a",16).toByteArray();
		initialize(key);
		
		encrypt(pt,0);
		assertTrue(Util.toHex(pt),Arrays.equals(ct, pt));
		
		decrypt(pt,0);
		assertTrue(Util.toHex(pt),Arrays.equals(pt, pt_orig));
	}
	
	@Test
	public void testVector192() throws InvalidKeyException {
	
		byte[] key =
			{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			 0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
			 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
		byte[] pt = Arrays.copyOf(pt_orig, pt_orig.length);

		byte[] ct =  new BigInteger("dda97ca4864cdfe06eaf70a0ec0d7191",16).toByteArray();
		ct = Arrays.copyOfRange(ct,1,ct.length);
		
		initialize(key);
		
		encrypt(pt,0);
		assertTrue(Util.toHex(pt),Arrays.equals(ct, pt));
		
		decrypt(pt,0);
		assertTrue(Util.toHex(pt),Arrays.equals(pt, pt_orig));
	}
	
	@Test
	public void testVector256() throws InvalidKeyException {
		
		byte[] key =
			{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			 0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
			 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
			 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
		byte[] pt = Arrays.copyOf(pt_orig, pt_orig.length);

		byte[] ct =  new BigInteger("8ea2b7ca516745bfeafc49904b496089",16).toByteArray();
		ct = Arrays.copyOfRange(ct,1,ct.length);
		
		initialize(key);
		
		encrypt(pt,0);
		assertTrue(Util.toHex(pt),Arrays.equals(ct, pt));
		
		decrypt(pt,0);
		assertTrue(Util.toHex(pt),Arrays.equals(pt, pt_orig));
	}
	
}
