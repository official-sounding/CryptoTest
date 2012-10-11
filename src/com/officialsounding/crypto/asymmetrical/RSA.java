package com.officialsounding.crypto.asymmetrical;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

import com.officialsounding.crypto.base.*;
import com.officialsounding.crypto.hash.SHA256;
import com.officialsounding.crypto.keys.RSAPrivateKey;
import com.officialsounding.crypto.keys.RSAPublicKey;
import com.officialsounding.crypto.util.Util;

public class RSA implements AsymCipherBase,SigningBase{

	private final static boolean debug = true;
	private final int sLen = 8;

	public boolean verify(PublicKey pubk, byte[] message, SignatureContainer signature) {
		if(pubk instanceof RSAPublicKey && signature instanceof RSASignature){
			RSAPublicKey rsapk = (RSAPublicKey) pubk;
			RSASignature sig = (RSASignature) signature;
			
			SHA256 sha = new SHA256();
			int hLen = sha.getOutputSize();
			
			byte[] em = RSAOperation(sig.getSignature(), rsapk.getE(), rsapk.getN()).toByteArray();
			
			if(debug){
				System.err.println("verify encodedmessage: "+Arrays.toString(em));
			}
			if(em[em.length-1] != (byte)0xbc){
				System.err.println(em[em.length-1]);
				return false;
			}
			
			byte[] H = Arrays.copyOfRange(em, em.length-1-hLen, em.length-1);
			byte[] maskedDB = Arrays.copyOfRange(em, 0, em.length-hLen-1);
			

			byte[] dbMask = MGF1(H, rsapk.getKeySizeBytes()-hLen -1);
			
			byte[] DB = Util.xorArray(maskedDB, dbMask);
			
			byte[] salt = Arrays.copyOfRange(DB, DB.length-sLen, DB.length);
			
			byte[] mHash = sha.digest(message);
			byte[] hPrime = sha.digest(Util.concatArray(new byte[8], Util.concatArray(mHash, salt)));
			
			if(debug){
				System.err.println("verify H: "+Arrays.toString(H));
				System.err.println("verify maskedDB: "+Arrays.toString(maskedDB));
				System.err.println("verify dbMask: "+Arrays.toString(dbMask));
				System.err.println("verify DB: "+Arrays.toString(DB));
				System.err.println("verify salt: "+Arrays.toString(salt));
			}

			return Arrays.equals(hPrime, H);
		}else{
			return false;
		}
	}

	public SignatureContainer sign(PrivateKey privk, byte[] message) throws InvalidKeyException {
		if(privk instanceof RSAPrivateKey){
			RSAPrivateKey rsapk = (RSAPrivateKey) privk;

			SHA256 sha = new SHA256();
			SecureRandom sr = new SecureRandom();

			byte[] salt = new byte[sLen];
			sr.nextBytes(salt);
			// encode message
			byte[] mHash = sha.digest(message);
			byte[] H = sha.digest(Util.concatArray(new byte[8], Util.concatArray(mHash, salt)));
			byte[] PS = new byte[(rsapk.getKeySizeBytes() - sLen - sha.getOutputSize() - 1)];
			PS[PS.length-1] = 0x01;

			byte[] dbMask = MGF1(H,PS.length+sLen);
			byte[] maskedDB = Util.xorArray(Util.concatArray(PS, salt), dbMask);

			if(debug){
				System.err.println("sign   H: "+Arrays.toString(H));
				System.err.println("sign   maskedDB: "+Arrays.toString(maskedDB));
				System.err.println("sign   dbMask: "+Arrays.toString(dbMask));
				System.err.println("sign   DB: "+Arrays.toString(Util.concatArray(PS, salt)));
				System.err.println("sign   salt: "+Arrays.toString(salt));
			}
			
			byte[] terminator = {(byte) 0xbc};
			byte[] encodedmessage = Util.concatArray(maskedDB, Util.concatArray(H, terminator));
			if(debug){
				System.err.println("sign   encodedmessage: "+Arrays.toString(encodedmessage));
			}
			BigInteger encodedhash = new BigInteger(encodedmessage);
			// encrypt signature
			BigInteger signature = RSAOperation(encodedhash,rsapk.getD(),rsapk.getN());
			return new RSASignature(signature);
		}else{
			return null;
		}
	}

	public AsymMessageContainer encrypt(byte[] message, PublicKey privk) throws InvalidKeyException {
		if(privk instanceof RSAPublicKey){
			RSAPublicKey rsapk = (RSAPublicKey) privk;

			// pad message and convert to a BigInteger
			BigInteger m = new BigInteger(OAEPPad(rsapk.getN().bitLength()/8,message,null));
			// compute c = m^e mod n
			BigInteger c = RSAOperation(m,rsapk.getE(),rsapk.getN());

			return new RSAMessage(c.toByteArray());
		}else{
			throw new InvalidKeyException("Private key is not a valid RSA key");
		}
	}

	public byte[] decrypt(AsymMessageContainer message, PrivateKey pubk)
	throws InvalidKeyException {
		if(pubk instanceof RSAPrivateKey && message instanceof RSAMessage){
			RSAPrivateKey rsapk = (RSAPrivateKey) pubk;

			BigInteger m = RSAOperation(new BigInteger(message.getCiphertext()),rsapk.getD(),rsapk.getN());
			return OAEPUnpad(m.toByteArray());
		}else{
			throw new InvalidKeyException("Public Key is not a valid RSA key");
		}
	}

	private BigInteger RSAOperation(BigInteger m, BigInteger base, BigInteger mod){
		if(m.bitLength() > mod.bitLength()){
			return BigInteger.ZERO;
		}
		return m.modPow(base, mod);
	}

	protected byte[] OAEPUnpad(byte[] paddedmessage){
		SHA256 sha = new SHA256();
		int hLen = sha.getOutputSize();

		if(debug){
			System.err.println("OAEPUnPad  input"+Arrays.toString(paddedmessage));
		}
		byte[] maskedX = Arrays.copyOfRange(paddedmessage, 1, paddedmessage.length - hLen);
		byte[] maskedY = Arrays.copyOfRange(paddedmessage, maskedX.length+1, maskedX.length+hLen+1);

		if(debug){
			System.err.println("OAEPUnPad maskedX"+Arrays.toString(maskedX));
			System.err.println("OAEPUnPad maskedY"+Arrays.toString(maskedY));
		}
		Util.xorArray(maskedY, sha.digest(maskedX),0,0,maskedY.length);
		Util.xorArray(maskedX, MGF1(maskedY,maskedX.length),0,0,maskedX.length);

		
		int i = maskedX.length-1;
		int beginmessage = 0;
		boolean probable = false;
		for(; i > hLen+1; i--){
			if(maskedX[i] == (byte)0x01){
				probable = true;
				beginmessage = i;
			}else if(maskedX[i] != (byte)0x00 && probable){
				probable = false;
			}
		}
		if(debug){
			System.err.println("OAEPUnpad X"+Arrays.toString(maskedX));
		}
		return Arrays.copyOfRange(maskedX, beginmessage+1, maskedX.length);
	}

	protected byte[] OAEPPad(int n, byte[] message, byte[] label){

		SHA256 sha = new SHA256();
		SecureRandom sr = new SecureRandom();

		int hLen = sha.getOutputSize();
		int mLen = message.length;
		int xLen = n - hLen - 1;


		byte[] output;
		byte[] maskedX;

		byte[] maskedY = new byte[hLen];

		byte[] lHash;
		if(label == null){
			lHash = sha.digest(new byte[0]);
		}else{
			lHash = sha.digest(label);
		}

		byte[] PS = new byte[xLen - hLen - mLen];
		byte[] xPad = Util.concatArray(lHash, PS);
		xPad[xPad.length -1] = 0x01;

		maskedX = Util.concatArray(xPad, message);

		sr.nextBytes(maskedY);

		if(debug){
			System.err.println("OAEPPad   X"+Arrays.toString(maskedX));
		}
		Util.xorArray(maskedX, MGF1(maskedY,maskedX.length),0,0,maskedX.length);
		Util.xorArray(maskedY, sha.digest(maskedX),0,0,maskedY.length);

		if(debug){
			System.err.println("OAEPPad   maskedX"+Arrays.toString(maskedX));
			System.err.println("OAEPPad   maskedY"+Arrays.toString(maskedY));
		}

		byte[] beginning = {(byte)0x01};
		output = Util.concatArray(beginning,maskedX);
		output = Util.concatArray(output,maskedY);

		if(debug){
			System.err.println("OAEPPad   output"+Arrays.toString(output));
		}
		return output;
	}

	private byte[] MGF1(byte[] seed, int maskLen){
		byte[] pad = new byte[0];
		byte[] C = new byte[4]; // 32 bit counter
		byte[] digest; 

		SHA256 sha = new SHA256();
		int hLen = sha.getOutputSize();
		int counterEnd = (int) Math.ceil(maskLen / hLen)+1;
		int counter = 0;

		while (counter < counterEnd) {
			digest = sha.digest(Util.concatArray(seed, C));

			pad = Util.concatArray(pad, digest);

			for (int i = C.length - 1; (++C[i] == 0) && (i > 0); i--) {
				// empty
			}
			counter++;
		}
		return Arrays.copyOf(pad,maskLen);
	}
}

