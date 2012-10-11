package com.officialsounding.crypto.cipher;

import java.util.*;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import com.officialsounding.crypto.util.Card;

public class Solitaire {

	List<Card> deck;
	boolean initialized;
	
	public Solitaire(){
		initialized = false;
		deck = Card.newDeck();
	}
	
	/**
	 * Initialize Key Deck with a text string 
	 * @param key - a string of english letters.  Whitespace ignored
	 * @throws InvalidKeyException if a non-letter or whitespace character is found in key
	 */
	public void initdeck(String key) throws InvalidKeyException{
		char[] keyarray = key.toCharArray();
		for(char keychar: keyarray){
			try{
				int keyvalue = charToAlphaPosition(keychar);
				//if the key value isn't a valid letter, don't use it
				doSolitareRound(true,keyvalue);
			}catch(IllegalArgumentException e){
				// a space character is technically illegal, but ignoring it is fine
				if(!Character.isWhitespace(keychar))
				throw new InvalidKeyException(e.getMessage()+": Invalid Characters in Key");
			}
		}
		initialized = true;
	}
	
	/**
	 * Initialize a key deck with a List of cards
	 * @param key
	 * @throws InvalidKeyException if there are not enough cards in the deck
	 */
	public void initdeck(List<Card> key) throws InvalidKeyException {
		if(key.size() != 54){
			throw new InvalidKeyException("Card Deck is wrong size");
		}
		Collections.copy(deck,key);
		initialized = true;
	}
	
	/**
	 * Initialize a key deck by randomly shuffling a standard deck
	 */
	public void initdeck(){
		//shuffle deck using CRNG
		SecureRandom rnd = new SecureRandom();
		Collections.shuffle(deck,rnd);
		initialized = true;
	}
	
	/**
	 * get the current key deck in its present state
	 * @return a list of Cards indicating the current key deck
	 */
	public List<Card> getDeckState(){
		return deck;
	}
	
	/**
	 * prints out the current state of the key deck
	 * currently unimplemented
	 */
	public void printDeckState(){
		
	}
	
	/**
	 * wrapper for doSolitareRound, to get a keystream value from the deck
	 * @return integer, representing the permutation value (1-26) of the card returned
	 */
	protected int getSolitareKeyStreamValue(){
		return doSolitareRound(false,0);
	}
	
	/**
	 * do a round of the Solitaire algorithm, potentially with the extra step involved with keying the deck
	 * @param keying indicate whether this round is being done to initially key the deck
	 * @param keyvalue the character from the passkey that is used in this round
	 * @return an integer, representing the permutation value (1-26) of the card returned 
	 */
	protected int doSolitareRound(boolean keying, int keyvalue){
		//get instances of the joker cards
		Card jokera = Card.cardByDeckPosition(52);
		Card jokerb = Card.cardByDeckPosition(53);
		
		//Step 1: move joker A down one card
		if(deck.indexOf(jokera) != 53){
			Collections.swap(deck, deck.indexOf(jokera), deck.indexOf(jokera)+1);
		}else{
			//remove joker A and place it below the top card
			deck.remove(deck.indexOf(jokera));
			deck.add(1,jokera);
		}
		
		//Step 2: move joker B down two cards
		//have to wrap around if the joker is near the bottom of the deck
		int newindex;
		if(deck.indexOf(jokerb) < 52)
			newindex = deck.indexOf(jokerb)+2;	
		else
			newindex = (deck.indexOf(jokerb)+2)%53;
		deck.remove(deck.indexOf(jokerb));
		deck.add(newindex,jokerb);
		
		//Step 3: a three way cut, determined by location of jokers
		int japos = deck.indexOf(jokera);
		int jbpos = deck.indexOf(jokerb);
		//if joker a is below joker b, swap the values
		if(japos > jbpos){
			int i = japos;
			japos = jbpos;
			jbpos = i;
		}
		
		//place cards as 2nd joker->end, 1st joker -> 2nd joker, beginning -> 1st joker
		List<Card> cutdeck = new ArrayList<Card>();
		cutdeck.addAll(deck.subList(jbpos+1,deck.size()));
		cutdeck.addAll(deck.subList(japos,jbpos+1));
		cutdeck.addAll(deck.subList(0,japos));
		deck = cutdeck;
		
		//Step 4: Count Cut, based on bottom value
		//take bottom card value number of cards from top, put them above bottom card
		deck = countCut(deck.get(deck.size()-1).getCardValue());
		
		//Step 4b: Count Cut, based on key value
		//if keying a deck, do a count cut based on the character value
		if(keying){
			deck = countCut(keyvalue);
		}
		//Step 5: return value of card the value of the top card number of cards down
		//returns permutation value, instead of pure card value
		return deck.get(deck.get(0).getCardValue()).getPermValue();
		
	}

	/**
	 * perform a "Count cut", removing the number of cards indicated by @param value from the top of the deck
	 * and placing these cards above the bottom card on the deck
	 * @param value
	 * @return
	 */
	protected List<Card> countCut(int value) {
		
		List<Card> cutdeck = new ArrayList<Card>();
		//first, put cards from the value to the bottom of the deck on top
		cutdeck.addAll(deck.subList(value,deck.size()-1));
		//then, put cards from the (original) top of the deck to the value
		cutdeck.addAll(deck.subList(0,value));
		//then, put the bottom card on the bottom
		cutdeck.add(deck.get(deck.size()-1));
		//return the new deck
		return cutdeck;
	}
	
	/**
	 * performs the Solitaire algorithm on a string of text
	 * @param str the string to be encrypted or decrypted
	 * @param encrypt indicate whether the string to be encrypted or decrypted
	 * @return the cipher text string, all uppercase charcters separated into groups of 5
	 */
	protected String solitaireString(String str, boolean encrypt){
		//turn the plaintext string into a character array
		char[] ptarr = str.toCharArray();
		
		//ctarr stores the ciphertext as it is built up from plaintext
		List<Character> ctarr = new ArrayList<Character>();
		int i = 0;
		int kv, chi;
		for(char ch: ptarr){
			
			try{
				//if the key value isn't a valid letter, don't use it
				chi = charToAlphaPosition(ch);
			
				//get keystream values until a non-joker value is received
				do{
				kv = getSolitareKeyStreamValue();
				}while(kv == 53);
				if(encrypt){
					chi+=kv;
					// if chi is greater than 'z', subtract 26
					if(chi > 26)
						chi-=26;
				}else{
					chi-=kv;
					// if chi is less than 'a', add 26
					if(chi < 1)
						chi+=26;
				}
				//add the 1-26 number to the array as an ascii value
				ctarr.add(Character.valueOf((char)(chi+64)));
				
				i++;
				//every 5th character, add a space to the ciphertext output
				if(i%5 == 0 && i < ptarr.length-1 && i != 0){
					ctarr.add(Character.valueOf(' '));
				}
			}catch(IllegalArgumentException e){
				//Ignore the exception for now
			}
		}
		
		//if plaintext (less spaces) is not evenly divisble into groups of 5
		//pad the last group out with "X" characters to make it a full group of 5
		if(encrypt && i % 5 != 0){
			for(i = 0; i < (5- (ptarr.length % 5)); i++)
			{
				chi = charToAlphaPosition('x');
				do{
					kv = getSolitareKeyStreamValue();
				}while(kv == 53);
				chi+=kv;
				if(chi > 26)
					chi-=26;
				ctarr.add(Character.valueOf((char)(chi+64)));
			}
		}
		
		//turn the List<Character> into a char array
		Character[] ct1 = ctarr.toArray(new Character[0]);
		char[] ct2 = new char[ct1.length];
		i = 0;
		for(Character n: ct1){
			ct2[i] = n;
			i++;
		}
		
		//return the character array as a string
		return new String(ct2);
	}
	
	/**
	 * wrapper method for solitaireString, used to decrypt text
	 * @param ct the ciphertext to be decrypted
	 * @return the plaintext, in all uppercase characters, grouped into sets of 5 letters
	 * @throws IllegalStateException if the cipher has not been initialized
	 */
	public String decrypt(String ct) throws IllegalStateException {
		if(initialized)
			return solitaireString(ct,false);
		else
			throw new IllegalStateException("Cipher not Initialized");
	}
	
	/**
	 * wrapper method for solitaireString, used to encrypt text
	 * @param pt the plaintext to be encrypted
	 * @return the ciphertext, in all uppercase characters, grouped into sets of 5 letters
	 * @throws IllegalStateException if the cipher has not been initialized
	 */
	public String encrypt(String pt) throws IllegalStateException {
		if(initialized)
			return solitaireString(pt,true);
		else
			throw new IllegalStateException("Cipher not Initialized");
	}
	
	/**
	 * output a the first few and last few elements of the key deck
	 * to ensure that the round operations are moving correctly
	 */
	protected void debugDeck(){
		//output the first 4 values of the deck
		for(int i = 0; i < 4; i++){
			if(deck.get(i).getCardValue() != 53){
				System.err.print(deck.get(i).getCardValue()+", ");
			}else{
				System.err.print(deck.get(i).rank()+", ");
			}
		}
		System.err.print("...");
		//output the last 4 values of the deck
		for(int i = 51; i < deck.size(); i++){
			if(deck.get(i).getCardValue() != 53){
				System.err.print(deck.get(i).getCardValue()+", ");
			}else{
				System.err.print(deck.get(i).rank()+", ");
			}
		}
		System.err.println();
	}
	
	/**
	 * convert an uppercase or lowercase letter to it's position in the alphabet
	 * @param x the character to be converted
	 * @return a number between 1 and 26
	 * @throws IllegalArgumentException if the character is not a letter
	 */
	protected int charToAlphaPosition(char x) throws IllegalArgumentException {
		
		if(!Character.isUpperCase(x) && !Character.isLowerCase(x)){
			throw new IllegalArgumentException(x+"is not a character in the alphabet");
		}
		//Character.getNumericValue outputs a number between 10 and 35
		//regardless if the letter is upper or lower case
		int n = Character.getNumericValue(x);
		n-=9;

		return n;
	}
}
