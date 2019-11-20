#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../frequency_analysis.h"

/* This function does not exist yet. It may be added or removed at a later date if the fast version is found to be sufficient.
 *
 * Calls the fast version for a baseline score
 * Also scans a dictionary of given words (1 per line) and cuts the score in half if less than 3 words in the dictionary exist in the text
 * This is a good heuristic to avoid blocks of random text that happen to have a good frequency distribution
 * However, blocks of english text without spaces will fail this check and should be inspected more closely manually or with an even slower method
 * Potentially, each byte could be checked for the presence of a word, but this would be time-consuming
 * Top 10k wordlist should be fine for most cases, but a more thorough full dictionary may be desired. Recommend cutting words < 4 characters long.
 */
unsigned int analyze_english_plaintext_viability(unsigned char *plaintext, unsigned char *dictionary){
	unsigned int rough_score = analyze_english_plaintext_viability_fast(plaintext);
	unsigned int new_score = rough_score;
	
	//if <3 words from dictionary in plaintext then new_score/=2
	/*
	create current_word pointer
	create char pointer of next dictionary word + null, i.e. {'v', 'a', 'l', '\0'}
	calloc current_word pointer of same length
	
	for each byte in plaintext
		memcpy(current_word, current dictionary word, strlen(current dictionary word));
	
	free used memory
	*/
	
	//use strstr to get next addresses?
	//need to get address of current word and the new beginning of the dictionary
	//cut out the linebreak and leave the trailing null byte that is already there from calloc
	/*for(){
		unsigned char *current_dictionary_word;
	}*/
	
	return new_score;
}

/* 
 * Examines a string of characters and scores the likelihood of the text being english text based on character frequency.
 * The algorithm gets the frequency of each letter, then puts the frequencies in their expected order.
 * If a frequency in slot N has only smaller values after it, 3 is added to the score. If it has an equal value after it, 1 is added. A greater value, 0.
 * This algorithm (and frequency analysis in general) will have unexpected results on sample sizes that are too small.
 * While frequencies of 0 are never counted, "asdf"
 * plaintext MUST be a valid string; This function is NOT binary safe - providing binary data causes undefined behavior.
 */
//TODO update frequency_count and frequency_count_ordered_by_expected to be arrays of integers instead of bytes
//Maybe use a struct? Experiment with it.
unsigned int analyze_english_plaintext_viability_fast(unsigned char *plaintext){
	unsigned char *frequency_chart_reference = "abcdefghijklmnopqrstuvwxyz";
	unsigned char *expected_frequency_chart = "etaoinshrdlcumwfgypbvkjxqz";
	//0 = a, 25 = z, do char-97
	unsigned char *frequency_count = calloc(26, 1);
	unsigned char *frequency_count_ordered_by_expected = calloc(26, 1);
	unsigned char current_char, score = 0;
	
	//get the lower-case version of our plaintext
	size_t i;
	for(i = 0; i < strlen(plaintext); i++){
		current_char = tolower(plaintext[i]);
		//skip non-alpha chars
		if(strchr(frequency_chart_reference, current_char) == (char *) NULL){
			continue;
		}
		frequency_count[current_char-97]++;
	}
	
	for(i = 0; i < 26; i++){
		//Get the current char, starting with e
		current_char = expected_frequency_chart[i];
		//0 -> e -> 4, 1 -> t -> 19
		frequency_count_ordered_by_expected[i] = frequency_count[current_char-97];
	}
	
	unsigned int j;
	unsigned char largest, equal;
	for(i = 0; i < 26; i++){
		//ignore values of 0 to prevent short data sets from being given erroneously high ratings
		if(frequency_count_ordered_by_expected[i] == 0){
			continue;
		}
		
		largest = 1;
		equal = 0;
		
		//check each subsequent count for larger or equal values
		for(j = i + 1; j < 26; j++){
			if(frequency_count_ordered_by_expected[j] > frequency_count_ordered_by_expected[i]){
				largest=0;
			}else if(frequency_count_ordered_by_expected[j] == frequency_count_ordered_by_expected[i]){
				largest=0;
				equal=1;
			}
		}
		
		if(largest){
			score+=3;
		}else if(equal){
			score++;
		}
	}
	
	free(frequency_count);
	free(frequency_count_ordered_by_expected);
	
	return (int) score;
}
