Deployed at: https://assuremoss.github.io/CVSSv4Calculator/index.html

Forked from: https://github.com/RedHatProductSecurity/cvss-v4-calculator

@Algorithm [Fabio Massacci](https://fabiomassacci.github.io/) (University of Trento and Vrije Universiteit Amsterdam), [Giorgio Di Tizio](https://giorgioditizio.github.io/) (University of Trento), 
     
Acknowledgements to Ben Edwards (Cyenthia) Mode 5, Jonathan Spring (DHS), Peter Mell (NIST) idea of mode 3
                   
How it works:

1. Read the vectors to be scored and fit it into a macro-vector
   * this is basically the orginal code from RedHat
2. Use a first lookup table for the ELO scores of the macrovectors 
   * this is in the file cvss_lookup.js (source Peter, Ben)
   * this has been adapted to make Base Score of the highest severity vector = 10.0
3. Use a second lookup table to find the highest severity vector(s) in the macrovectors
   * this is in the file max_composed.js (Source Fabio, Giorgio)
   * EQ3 and EQ6 are merged as they are not independent
4. Compute the hamming distance from the highest severity vector in the macrovector and the vector to be scored
   * The BaseScore function come in two variants 
   * the vanilla version use 0.1 increments to compute the Hamming distance (Source Fabio)
   * If you tick the box in the interface the Hamming distance is weighted by scores of an ELO algorithm (data source Ben).
5. The final score is 
   * elo(higheste severity vector of the macro vector) - hamming distance(highest severity vector in the macro vector,vector to be scored)


