Deployed at: https://assuremoss.github.io/CVSSv4Calculator/index.html

Forked from: https://github.com/RedHatProductSecurity/cvss-v4-calculator

@Algorithm [Fabio Massacci](https://fabiomassacci.github.io/) (University of Trento and Vrije Universiteit Amsterdam), [Giorgio Di Tizio](https://giorgioditizio.github.io/) (University of Trento), 
     
Acknowledgements to Ben Edwards (Cyenthia), Jonathan Spring (DHS), Peter Mell (NIST) 
                   
How it works:

1. Read the vectors to be scored and fit it into a macro-vector
2. Use a first lookup table for the ELO scores of the macrovectors (source Peter, Ben)
3. Use a second lookup table to find the highest severity vector(s) in the macrovectors
4. Compute the hamming distance from the highest severity vector and the vector to be scored
5. The final score is elo(higheste severity vector of the macro vector) - hamming distance(highest severity vector in the macro vector,vector to be scored)

If you tick the box the hamming distance is not multiples of 0.1 but it is weighted by scores of an ELO algorithm on SIG scored vectors (source Ben).

