package com.officialsounding.crypto.util;

import java.util.*;

public class Card {
	public enum Rank { ACE(1), DEUCE(2), THREE(3), FOUR(4), FIVE(5), SIX(6),
		SEVEN(7), EIGHT(8), NINE(9), TEN(10), JACK(11), QUEEN(12), KING(13), A(53), B(53);

		Rank(int value){
			this.value = value;
		}
		private final int value;
		public int value(){ return value; }
	}

	public enum Suit { CLUBS(0), DIAMONDS(13), HEARTS(26), SPADES(39), JOKER(0);
		Suit(int value){
			this.value = value;
		}
		private final int value;
		public int value(){ return value; }
	}

	private final Rank rank;
	private final Suit suit;
	public Card(Rank rank, Suit suit) {
		this.rank = rank;
		this.suit = suit;
	}

	public Rank rank() { return rank; }
	public Suit suit() { return suit; }
	
	public String toString() { return rank + " of " + suit; }
	
	public static Rank getRankByNumber(int n){
		return Rank.values()[n-1];
	}
	public int getCardValue(){
		return rank.value() + suit.value();
	}
	
	public int getPermValue(){
		if(suit.value() > 13){
			return rank.value() + suit.value() - 26;
		}
		return (rank.value() + suit.value());
	}

	private static final List<Card> protoDeck = new ArrayList<Card>();

	// Initialize prototype deck
	static {
		for (Suit suit : Suit.values())
			for (Rank rank : Rank.values()){
				if(rank.value < 14 && suit != Suit.JOKER)
					protoDeck.add(new Card(rank, suit));
			}
		protoDeck.add(new Card(Rank.A,Suit.JOKER));
		protoDeck.add(new Card(Rank.B,Suit.JOKER));
	}

	public static ArrayList<Card> newDeck() {
		return new ArrayList<Card>(protoDeck); // Return copy of prototype deck
	}
	
	public static Card cardByDeckPosition(int value){
		return protoDeck.get(value);
	}
	
	@Override
	public boolean equals(Object o){
		if(o instanceof Card){
			if(((Card) o).rank() != rank){
				return false;
			}
			else if(((Card) o).suit() != suit){
				return false;
			}else{
				return true;
			}
		}else{
			return false;
		}
	}
}
