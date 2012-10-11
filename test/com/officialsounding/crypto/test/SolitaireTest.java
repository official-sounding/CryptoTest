package com.officialsounding.crypto.test;

import static org.junit.Assert.*;

import java.security.InvalidKeyException;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.officialsounding.crypto.cipher.Solitaire;
import com.officialsounding.crypto.util.Card;

public class SolitaireTest extends Solitaire{

	List<Card> deck;
	@Before
	public void setUp() throws Exception {
		deck = Card.newDeck();
	}

	@Test
	public void Decktest() {
		assertTrue(deck.size() == 54);
		assertTrue(deck.get(0).getCardValue() == 1);
		assertTrue(deck.get(deck.size()-1).getCardValue() == 53);
	}
	
	@Test
	public void RoundTest() throws InvalidKeyException {
		initdeck(deck);
		int[] values = new int[10];
		for(int i = 0; i < 10; i++){
			values[i] = getSolitareKeyStreamValue();
		}
		
		for(int x: values){
			System.out.print(x+", ");
		}
		System.out.println();
		
		assertTrue(values[0]==4);
		assertTrue(values[1]==23);
	}
	
	@Test
	public void charToAlphaTest(){
		assertTrue("1: "+charToAlphaPosition('A'),charToAlphaPosition('A') == 1);
		assertTrue("2: "+charToAlphaPosition('a'),charToAlphaPosition('a') == 1);
		assertTrue("3: "+charToAlphaPosition('z'),charToAlphaPosition('z') == 26);
	}

	@Test
	public void keyingTest() throws InvalidKeyException{
		initdeck("FOO");
		int[] values = new int[10];
		for(int i = 0; i < 10; i++){
			values[i] = getSolitareKeyStreamValue();
		}
		
		for(int x: values){
			System.out.print(x+", ");
		}
		System.out.println();
		
		assertTrue(values[0]==8);
		assertTrue(values[1]==19);
		
	}
	
	@Test
	public void encryptTest() throws InvalidKeyException{
		initdeck("FOO");
		String ct = encrypt("AAAAA AAAAA");
		System.out.println(ct);
		assertTrue(ct,ct.equals("ITHZU JIWGR"));
	}
	
	@Test
	public void decryptTest() throws InvalidKeyException{
		initdeck("FOO");
		String pt = decrypt("ITHZU JIWGR");
		assertTrue(pt,pt.equals("AAAAA AAAAA"));
	}
	
	@Test
	public void testVector1() throws InvalidKeyException{
		initdeck("f");
		String ct = encrypt("AAAAAAAAAAAAAAA");
		assertTrue(ct, ct.equals("XYIUQ BMHKK JBEGY"));
	}
	
	@Test
	public void testVector2() throws InvalidKeyException{
		initdeck("bcd");
		String ct = encrypt("AAAAAAAAAAAAAAA");
		assertTrue(ct, ct.equals("FMUBY BMAXH NQXCJ"));
	}	
	
	@Test
	public void testVector3() throws InvalidKeyException{
		initdeck("cryptonomicon");
		String ct = encrypt("SOLITAIRE");
		assertTrue(ct, ct.equals("KIRAK SFJAN"));
	}	
	
}
