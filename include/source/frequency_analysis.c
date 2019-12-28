#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <float.h>

#include "../frequency_analysis.h"

//A through Z in order, then space
static double expected_frequencies[27] = {0.0651738, 0.0124248, 0.0217339, 0.0349835, 0.1041442, 0.0197881, 0.0158610, 0.0492888, 0.0558094, 0.0009033, 0.0050529, 0.0331490, 0.0202124, 0.0564513, 0.0596302, 0.0137645, 0.0008606, 0.0497563, 0.0515760, 0.0729357, 0.0225134, 0.0082903, 0.0171272, 0.0013692, 0.0145984, 0.0007836, 0.1918182};

/* 
 * Old method was too unreliable and beyond repair without some kind of overall analysis instead of looking only at individual cases.
 * We now take into account every case with appropraite weight.
 * Under the hood the test is still comparing expected to actual results, but in a more sophisticated and accurate way than my prior crude approximations.
 * Smaller values are a closer match.
 * This function is binary safe - any unprintable characters cause a return value of DBL_MAX, the lowest possible priority.
 */
double analyze_english_plaintext_viability(char *text){
	double *actual_frequencies = malloc(27*sizeof(double));
	size_t ignored = 0;
	
	size_t i;
	for(i = 0; i < 27; i++) actual_frequencies[i] = 0;
	
	unsigned char current_char;
	for(i = 0; i < strlen(text); i++){
		current_char = text[i];
		if(current_char >= 65 && current_char <= 90){
			//Lower case
			actual_frequencies[current_char - 65]++;
		}else if(current_char >= 97 && current_char <= 122){
			//Upper case
			actual_frequencies[current_char - 97]++;
		}else if(current_char >= 32 && current_char <= 126){
			if(current_char == 32){
				//space
				actual_frequencies[26]++;
			}else{
				//Numbers and punctuation
				ignored++;
			}
		}else if(current_char == '\t' || current_char == '\n'){
			//Whitespace
			//Can include '\r' for CRLF, but causes problems for LF text. Reject it, at least for now.
			ignored++;
		}else{
			//Contains unprintable characters. Abort with lowest possible priority.
			printf("Unprintable character %#02hhx\n", current_char);
			free(actual_frequencies);
			return DBL_MAX;
		}
	}
	
	double chi_squared = 0, observed, expected, difference, diff_squared;
	size_t length = strlen(text) - ignored;
	for(i = 0; i < 27; i++){
		observed = actual_frequencies[i];
		expected = length * expected_frequencies[i];
		difference = observed - expected;
		diff_squared = difference*difference;
		//printf("Adding %lf to chi2 with O=%lf E=%lf D^2=%lf c=%c\n", diff_squared / expected, observed, expected, diff_squared, i+97);
		chi_squared += diff_squared / expected;
	}
	
	free(actual_frequencies);
	
	return chi_squared;
}

/* 
 * This function does not use chi-squared. Instead, the frequency of each letter is added up and used raw.
 * This scoring method is the inverse of the above, i.e. higher score is better.
 * This function is binary safe - any unprintable characters cause a return value of 0, the lowest possible priority.
 */
double analyze_english_plaintext_viability_fast(char *text){
	double *actual_frequencies = malloc(27*sizeof(double));
	
	size_t i;
	for(i = 0; i < 27; i++) actual_frequencies[i] = 0;
	
	char current_char;
	for(i = 0; i < strlen(text); i++){
		current_char = (unsigned char) text[i];
		if(current_char >= 65 && current_char <= 90){
			//Lower case
			actual_frequencies[current_char - 65]++;
		}else if(current_char >= 97 && current_char <= 122){
			//Upper case
			actual_frequencies[current_char - 97]++;
		}else if(current_char >= 32 && current_char <= 126){
			if(current_char == 32){
				//space
				actual_frequencies[26]++;
			}
		}else if(current_char != '\t' && current_char != '\n'){
			//Contains unprintable characters. Abort with lowest possible priority.
			//printf("Unprintable character: %#02hhx\n", current_char);
			free(actual_frequencies);
			return 0;
		}
	}
	
	double total_score = 0;
	for(i = 0; i < 27; i++){
		//use the expected frequencies as a simple scoring system
		total_score += actual_frequencies[i] * expected_frequencies[i];
	}
	
	free(actual_frequencies);
	return total_score;
}
