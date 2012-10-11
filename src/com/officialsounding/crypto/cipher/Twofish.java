package com.officialsounding.crypto.cipher;

import java.security.InvalidKeyException;
import java.util.Arrays;

import com.officialsounding.crypto.base.CipherBase;
import com.officialsounding.crypto.util.GF256;
import com.officialsounding.crypto.util.Util;

public class Twofish implements CipherBase {

	private byte[][] S = null;
	private int[] K = new int[40];
	private boolean initialized = false;
	private final int BLOCKSIZE = 16;
	private final int rounds = 16;
	
	private final byte[] MDS  = 
	{
			(byte) 0x01, (byte) 0xEF, (byte) 0x5B, (byte) 0x5B,
			(byte) 0x5B, (byte) 0xEF, (byte) 0xEF, (byte) 0x01,
			(byte) 0xEF, (byte) 0x5B, (byte) 0x01, (byte) 0xEF,
			(byte) 0xEF, (byte) 0x01, (byte) 0xEF, (byte) 0x5B,
	};

	public void encrypt(byte[] in, int offset) throws IllegalStateException {
		if(!initialized)
			throw new IllegalStateException("Cipher not Initialized");
		int[] block = new int[4];
		int temp;
		// split block into an array of ints, and perform input whitening
		for(int i = 0; i < 4; i++){
			for(int j = 0; j < 4; j++){
				block[i] <<= 8;
				block[i]  |= (in[offset++] & 0xff);
			}
			block[i] ^= K[i];
		}
		
		//perform round operations
		for(int i = 0; i < rounds; i+=2){
			round(block,i);
			round(block,i+1);
		}
		
		//undo last swap
		temp = block[3];
		block[3] = block[1];
		block[1] = temp;
		
		temp = block[2];
		block[2] = block[0];
		block[2] = temp;
		
		//return to byte array, 
		for(int i = 3; i >= 0; i--){
			block[i] ^= K[4+i];
			for(int j = 0; j < 4; j++){
				in[--offset] = (byte)(block[i] & 0xff);
				block[i] >>= 8;
			}
		}
	}

	public void decrypt(byte[] in, int offset) throws IllegalStateException {
		if(!initialized)
			throw new IllegalStateException("Cipher not Initialized");
		

	}

	private void round(int[] block, int round){

		int a,b,c,d;
		a = g(block[0]);
		b = g(Util.lr(block[1],8));
		
		//PHT
		a += b;
		b += a;
		
		//mix in round keys
		a += K[2*round+8];
		b += K[2*round+9];
		
		//xor results of F with c and d and perform rotations
		c = Util.rr(a ^ block[2],1);
		d = b ^ Util.lr(block[3],1);
		
		//swap elements
		block[0] = c;
		block[1] = d;
		block[2] = a;
		block[3] = b;
 	}
	
	private int g(int in){
		byte[] inbytes = Util.intToByteArr(in);
		//S-box lookups
		for(int i = 0; i < 4; i++){
			inbytes[i] = S[i][inbytes[i]];
		}
		
		//MDS transformation
		byte[] temp = Arrays.copyOf(inbytes, inbytes.length);
		int n = 0;
		for(byte x: inbytes){
			x = GF256.mult(temp[0],MDS[4*n]);
			for(int i = 1;i < 4;i++){
				x ^= GF256.mult(temp[i],MDS[4*n+i]);
			}
			n++;
		}
		
		return Util.byteArrayToInt(inbytes);
		
	}
	
	public void initialize(byte[] key) throws InvalidKeyException {
		// TODO Auto-generated method stub

	}

	public CipherBase getCopy() {
		return new Twofish();
	}

	public int getBlockSize() {
		return BLOCKSIZE;
	}
}
