package com.officialsounding.crypto.test;

import static org.junit.Assert.*;

import java.security.InvalidKeyException;

import org.junit.Before;
import org.junit.Test;

import com.officialsounding.crypto.cipher.Mirdek;
import com.officialsounding.crypto.util.Card;
import com.officialsounding.crypto.util.Card.Rank;
import com.officialsounding.crypto.util.Card.Suit;

public class MirdekTest extends Mirdek{

	String IV = "IPDZO WKGST VARME QYBCF JNHUL";
	String Key = "KEYPHRASE";
	String PT1 = "PLAIN TEXTX";
	String PT2 = "PLAINTEXT";
	String PT3 = "PLAIN, TEXT";
	String CT =  IV+" OYNYG IMYOE";
	String CTnoIV = "OYNYG IMYOE";
	String badKey = "fasdf$%312";
	
	@Before
	public void setUp() throws Exception {
		initalizeDeck(true,IV);
	}

	@Test
	public void testEncrypt() throws InvalidKeyException{
		initialize(Key,IV);
		String ct = encrypt(PT3);
		assertTrue(CT.equals(ct));
	}
	
	@Test
	public void testDecrypt() throws InvalidKeyException{
		initialize(Key,IV);
		String pt = decrypt(CT,true);
		assertTrue(PT1.equals(pt));
	}
	
	
	@Test
	public void testInitializeDeck() throws InvalidKeyException {
		 assertTrue(charToCard('X', true).equals(r.get(0)));
		 assertTrue(charToCard('I', true).equals(r.get(r.size()-1)));
		 initalizeDeck(false,new String());
		 assertTrue(iv.length() == 29);
	}
	@Test
	public void testKeyDeck() throws InvalidKeyException {
		keyDeck(Key);
		assertTrue(charToCard('T', false).equals(l.get(0)));
		assertTrue(charToCard('V', false).equals(l.get(l.size()-1)));
	}

	@Test
	public void testMixDeck() throws InvalidKeyException {
		keyDeck(Key);
		mixDeck();
		assertTrue(charToCard('T', false).equals(l.get(0)));
		assertTrue(charToCard('V', false).equals(l.get(l.size()-1)));
		assertTrue(charToCard('P', true).equals(r.get(0)));
		assertTrue(charToCard('X', true).equals(r.get(r.size()-1)));
	}

	@Test
	public void testMoveDeckFlip() {
		moveDeck(l,d,true);
		assertTrue(charToCard('Z', false).equals(d.get(0)));
		assertTrue(charToCard('A', false).equals(d.get(d.size()-1)));
	}
	
	@Test
	public void testMoveDeckNoFlip(){
		moveDeck(l,d,false);
		assertTrue(charToCard('A', false).equals(d.get(0)));
		assertTrue(charToCard('Z', false).equals(d.get(d.size()-1)));
	}

	@Test
	public void testCountedCut() throws InvalidKeyException {
		countedCut();
		assertTrue(charToCard('Y', false).equals(l.get(0)));
		assertTrue(charToCard('X', false).equals(l.get(l.size()-1)));
		assertTrue(charToCard('L', true).equals(r.get(0)));
		assertTrue(charToCard('I', true).equals(r.get(r.size()-1)));
		assertTrue(d.size()==1);
	}

	@Test
	public void testLetterSearchEven() throws InvalidKeyException {
		countedCut();
		int count = letterSearch('K',false);
		assertTrue(count+" ",count == 13);
		assertTrue(charToCard('L', false).equals(l.get(0)));
		assertTrue(charToCard('Z', false).equals(l.get(l.size()-1)));
	}

	@Test
	public void testLetterSearchOdd() throws InvalidKeyException {
		countedCut();
		int count = letterSearch('L',false);
		assertTrue(count+" ",count == 14);
		assertTrue(charToCard('M', false).equals(l.get(0)));
		assertTrue(charToCard('Y', false).equals(l.get(l.size()-1)));
	}
	
	@Test
	public void testCharToCard() {
		assertTrue(charToCard('a',true).equals(new Card(Rank.ACE,Suit.SPADES)));
		assertTrue(charToCard('a',false).equals(new Card(Rank.ACE,Suit.CLUBS)));
		assertTrue(charToCard('x',true).equals(new Card(Rank.JACK,Suit.DIAMONDS)));
		assertTrue(charToCard('x',false).equals(new Card(Rank.JACK,Suit.HEARTS)));
	}
	
	@Test(expected= InvalidKeyException.class) public void testBadKey() throws InvalidKeyException { 
	     keyDeck(badKey);
	}
	
	@Test(expected= InvalidKeyException.class) public void testBadIV() throws InvalidKeyException { 
	     initalizeDeck(true,badKey);
	}	
}
