#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <float.h>

#include "../frequency_analysis.h"

//A through Z in order
static double expected_frequencies[26] = {0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074};

/* 
 * Old method was too unreliable and beyond repair without some kind of overall analysis instead of looking only at individual cases.
 * We now take into account every case with appropraite weight.
 * Under the hood the test is still comparing expected to actual results, but in a more sophisticated and accurate way than my prior crude approximations.
 * Smaller values are a closer match.
 * This function expects valid ASCII data. It is NOT binary safe.
 */
double analyze_english_plaintext_viability(char *text){
	double *actual_frequencies = malloc(26*sizeof(double));
	unsigned int ignored = 0;
	
	size_t i;
	for(i = 0; i < 26; i++) actual_frequencies[i] = 0;
	
	unsigned char current_char;
	for(i = 0; i < strlen(text); i++){
		current_char = tolower(text[i]);
		if(current_char >= 97 && current_char <= 122){
			//Letters already converted to lowercase
			actual_frequencies[current_char - 97]++;
		}else if(current_char >= 32 && current_char <= 126){
			//Numbers and punctuation
			ignored++;
		}else if(current_char == '\t' || current_char == '\n'){
			//Whitespace
			//Can include '\r' for CRLF, but causes problems for LF text. Reject it, at least for now.
			ignored++;
		}else{
			//Contains unprintable characters. Abort with lowest possible priority.
			return DBL_MAX;
		}
	}
	
	double chi_squared = 0, observed, expected, difference;
	unsigned long hits = strlen(text) - ignored;
	for(i = 0; i < 26; i++){
		observed = actual_frequencies[i];
		expected = hits * expected_frequencies[i];
		difference = observed - expected;
		//printf("Adding %lf to chi2 with O=%lf E=%lf D=%lf\n", (difference*difference) / expected, observed, expected, difference);
		chi_squared += (difference*difference) / expected;
	}
	
	free(actual_frequencies);	
	return chi_squared;
}
