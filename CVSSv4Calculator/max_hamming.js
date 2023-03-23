/**
 * Forked from https://github.com/RedHatProductSecurity/cvss-v4-calculator
 * Hamming computed by Fabio Massacci and Giorgio Di Tizio from data by Jonathan Spring (DHS) and Peter Mell (NIST) 
 * eq3 merges EQ3 and EQ6 from the SIG
 */

//max hamming distance between EQ sets (+1)

maxHamming = {
	"eq1" : {
		"0" : 1,
		"1" : 4,
		"2" : 5
	},
	"eq2" : {
		"0" : 1,
		"1" : 2
	},
	"eq3" : {
		"0" : {"0": 7, "1": 6},
		"1" : {"0": 8, "1": 9},
		"2" : {"1": 10}
	},
	"eq4" : {
		"0" : 6,
		"1" : 5,
		"2" : 4

	},
	"eq5" : {
		"0" : 1,
		"1" : 1,
		"2" : 1
	},
}
