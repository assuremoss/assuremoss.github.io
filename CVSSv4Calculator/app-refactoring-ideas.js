/**
 * Forked from https://github.com/RedHatProductSecurity/cvss-v4-calculator
 * BaseScore algorithm from Fabio Massacci (University of Trento and Vrije Universiteit Amsterdam) and Giorgio Di Tizio (University of Trento)
 * Data for the Weighted Hamming Distance by Ben Edwards (Cyenthia)
 
 * CONTAINS SOME REFACTORING IDEAS TO BE ADDED
 
 
 */

const app = Vue.createApp({
    data() {
        return {
...
        }
    },
    methods: {
...
       m(metric) {
            selected = this.cvssSelected[metric]

            // E:X is the same as E:A
            if(metric == "E" && selected == "X") {
                return "A"
            }

            // The three security requirements metrics have X equivalent to H.
            // CR:X is the same as CR:H
            if(metric == "CR" && selected == "X") {
                return "H"
            }
            // IR:X is the same as IR:H
            if(metric == "IR" && selected == "X") {
                return "H"
            }
            // AR:X is the same as AR:H
            if(metric == "AR" && selected == "X") {
                return "H"
            }

            // All other environmental metrics just overwrite base score values,
            // so if they’re not defined just use the base score value.
            if(Object.keys(this.cvssSelected).includes("M" + metric)) {
                modified_selected = this.cvssSelected["M" + metric]
                if(modified_selected != "X" && modified_selected != "S") {
                    return modified_selected
                }
            }

            return selected
        },
 ...
 computed: {
        vector() {
            value = "CVSS:4.0"
            for(metric in this.cvssSelected) {
                selected = this.cvssSelected[metric]
                if(selected != "X") {
                    value = value.concat("/" + metric + ":" + selected)
                }
            }
            return value
        },
        MaxBaseScore(){
            lookup = this.macroVector
            // Exception for no impact on system
            if(lookup.includes("33")) {
                return "0.0"
            }
            this.max_base_value = this.cvssLookupData[lookup]
            return this.max_base_value
        },
        macroVector() {
            // EQ1: 0-AV:N and PR:N and UI:N
            //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
            //      2-AV:P or not(AV:N or PR:N or UI:N)

            if(this.m("AV") == "N" && this.m("PR") == "N" && this.m("UI") == "N") {
                eq1 = "0"
            }
            else if((this.m("AV") == "N" || this.m("PR") == "N" || this.m("UI") == "N")
                    && !(this.m("AV") == "N" && this.m("PR") == "N" && this.m("UI") == "N")
                    && !(this.m("AV") == "P")) {
                eq1 = "1"
            }
            else if(this.m("AV") == "P"
                    || !(this.m("AV") == "N" || this.m("PR") == "N" || this.m("UI") == "N")) {
                eq1 = "2"
            }
            else {
                console.log("Error computing EQ1")
                eq1 = 9
            }

            // EQ2: 0-(AC:L and AT:N)
            //      1-(not(AC:L and AT:N))

            if(this.m("AC") == "L" && this.m("AT") == "N") {
                eq2 = "0"
            }
            else if(!(this.m("AC") == "L" && this.m("AT") == "N")) {
                eq2 = "1"
            }
            else {
                console.log("Error computing EQ2")
                eq2 = 9
            }

            // EQ3 Revised: 0-(VC:H and VI:H)
            //              1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
            //              2-not (VC:H or VI:H or VA:H)
            //              3-(VC:N and VI:N and VA:N and SC:N and SI:N and SA:N)  PRIORITY

            if(this.m("VC") == "N" && this.m("VI") == "N" && this.m("VA") == "N"
               && this.m("SC") == "N" && this.m("SI") == "N" && this.m("SA") == "N") {
                eq3 = 3
            }
            else if(this.m("VC") == "H" && this.m("VI") == "H") {
                eq3 = 0
            }
            else if(!(this.m("VC") == "H" && this.m("VI") == "H")
                    && (this.m("VC") == "H" || this.m("VI") == "H" || this.m("VA") == "H")) {
                eq3 = 1
            }
            else if(!(this.m("VC") == "H" || this.m("VI") == "H" || this.m("VA") == "H")) {
                eq3 = 2
            }
            else {
                console.log("Error computing EQ3")
                eq3 = 9
            }

            // EQ4: 0-(MSI:S or MSA:S)
            //      1-(SC:H or SI:H or SA:H and not(MSI:S or MSA:S))
            //      2-((SC:L or N) and (SI:L or N) and (SA:L or N))
            //      3-(VC:N and VI:N and VA:N and SC:N and SI:N and SA:N)  PRIORITY

            if(this.m("VC") == "N" && this.m("VI") == "N" && this.m("VA") == "N"
               && this.m("SC") == "N" && this.m("SI") == "N" && this.m("SA") == "N") {
                eq4 = 3
            }
            else if(this.m("MSI") == "S" || this.m("MSA") == "S") {
                eq4 = 0
            }
            else if(this.m("SC") == "H" || this.m("SI") == "H"
                    || this.m("SA") == "H" && !(this.m("MSI") == "S" || this.m("MSA") == "S")) {
                eq4 = 1
            }
            else if(((this.m("SC") == "L" || this.m("SC") == "N")
                     && (this.m("SI") == "L" || this.m("SI") == "N")
                     && (this.m("SA") == "L" || this.m("SA") == "N"))) {
                eq4 = 2
            }
            else {
                console.log("Error computing EQ4")
                eq4 = 9
            }

            // EQ5: 0-E:A
            //      1-E:P
            //      2-E:U

            if(this.m("E") == "A") {
                eq5 = 0
            }
            else if(this.m("E") == "P") {
                eq5 = 1
            }
            else if(this.m("E") == "U") {
                eq5 = 2
            }
            else {
                console.log("Error computing EQ5")
                eq5 = 9
            }

            // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
            //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

            if((this.m("CR") == "H" && this.m("VC") == "H")
               || (this.m("IR") == "H" && this.m("VI") == "H")
               || (this.m("AR") == "H" && this.m("VA") == "H")) {
               eq6 = 0
            }
            else if(!((this.m("CR") == "H" && this.m("VC") == "H")
                      || (this.m("IR") == "H" && this.m("VI") == "H")
                      || (this.m("AR") == "H" && this.m("VA") == "H"))) {
               eq6 = 1
            }
            else {
                console.log("Error computing EQ6")
                eq6 = 9
            }

            return eq1 + eq2 + eq3 + eq4 + eq5 +eq6
        },
		TotalHammingDistance(upper_vector,lower_vector){
                hamming_distance_AV = AV_levels[lower_vector("AV")]-AV_levels[this.extractValueMetric("AV",upper_vector)]
                hamming_distance_PR = PR_levels[lower_vector("PR")]-PR_levels[this.extractValueMetric("PR",upper_vector)]
                hamming_distance_UI = UI_levels[lower_vector("UI")]-UI_levels[this.extractValueMetric("UI",upper_vector)]

                hamming_distance_AC = AC_levels[lower_vector("AC")]-AC_levels[this.extractValueMetric("AC",upper_vector)]
                hamming_distance_AT = AT_levels[lower_vector("AT")]-AT_levels[this.extractValueMetric("AT",upper_vector)]

                hamming_distance_VC = VC_levels[lower_vector("VC")]-VC_levels[this.extractValueMetric("VC",upper_vector)]
                hamming_distance_VI = VI_levels[lower_vector("VI")]-VI_levels[this.extractValueMetric("VI",upper_vector)]
                hamming_distance_VA = VA_levels[lower_vector("VA")]-VA_levels[this.extractValueMetric("VA",upper_vector)]   


                if(lower_vector("MSI") == "S" && lower_vector("MSA")=="S"){
                    //use MSI and MSA
                    hamming_distance_SI = SI_levels[lower_vector("MSI")]-SI_levels[this.extractValueMetric("SI",upper_vector)]             
                    hamming_distance_SA = SA_levels[lower_vector("MSA")]-SA_levels[this.extractValueMetric("SA",upper_vector)]  
                }
                else if (lower_vector("MSI") == "S"){
                    //only MSI set to S
                    hamming_distance_SI = SI_levels[lower_vector("MSI")]-SI_levels[this.extractValueMetric("SI",upper_vector)]
                    hamming_distance_SA = SA_levels[lower_vector("SA")]-SA_levels[this.extractValueMetric("SA",upper_vector)]
                }
                else if(lower_vector("MSA") == "S"){
                    //only MSA set to S
                    hamming_distance_SI = SI_levels[lower_vector("SI")]-SI_levels[this.extractValueMetric("SI",upper_vector)]
                    hamming_distance_SA = SA_levels[lower_vector("MSA")]-SA_levels[this.extractValueMetric("SA",upper_vector] 
                }
                else {
                    //none set to S
                    hamming_distance_SI = SI_levels[lower_vector("SI")]-SI_levels[this.extractValueMetric("SI",upper_vector)]     
                    hamming_distance_SA = SA_levels[lower_vector("SA")]-SA_levels[this.extractValueMetric("SA",upper_vector)]  
                }
                hamming_distance_SC = SC_levels[lower_vector("SC")]-SC_levels[this.extractValueMetric("SC",upper_vector)]

                hamming_distance_CR = CR_levels[lower_vector("CR")]-CR_levels[this.extractValueMetric("CR",upper_vector)]
                hamming_distance_IR = IR_levels[lower_vector("IR")]-IR_levels[this.extractValueMetric("IR",upper_vector)]
                hamming_distance_AR = AR_levels[lower_vector("AR")]-AR_levels[this.extractValueMetric("AR",upper_vector)]
				
				return hamming_distance_AV + hamming_distance_PR + hamming_distance_UI + hamming_distance_AC + hamming_distance_AT + hamming_distance_VC + hamming_distance_VI + hamming_distance_VA + hamming_distance_SC  + hamming_distance_SI +  hamming_distance_CR + hamming_distance_IR + hamming_distance_AR
		},
		HigherVectors(lookupMacroVector) {
            //get all max vector for the eq
            eq1_maxes = this.getvalueEqLookup(lookupMacroVector,0)
            eq2_maxes = this.getvalueEqLookup(lookupMacroVector,1)
            eq3_eq6_maxes = this.getvalueEqLookup(lookupMacroVector,2)[lookupMacroVector[5]]
            eq4_maxes = this.getvalueEqLookup(lookupMacroVector,3)
            eq5_maxes = this.getvalueEqLookup(lookupMacroVector,4)

            //compose them
            max_vectors = []
            for (eq1_max of eq1_maxes){
                for (eq2_max of eq2_maxes){
                    for (eq3_eq6_max of eq3_eq6_maxes){
                        for (eq4_max of eq4_maxes){
                            for (eq5max of eq5_maxes){
                                    max_vectors.push(eq1_max+eq2_max+eq3_eq6_max+eq4_max+eq5max)
                            }
                        }
                    }
                }
            }
			return max_vectors
		},
		LowerVectors(lookupMacroVector) {
            eq1_val = parseInt(lookupMacroVector[0])
            eq2_val = parseInt(lookupMacroVector[1])
            eq3_val = parseInt(lookupMacroVector[2])
            eq4_val = parseInt(lookupMacroVector[3])
            eq5_val = parseInt(lookupMacroVector[4])
            eq6_val = parseInt(lookupMacroVector[5])

			min_vectors = []
			
            //compute next lower macro, it can also not exist
            eq1_next_lower_macro = "".concat(eq1_val+1,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val)
			min_vectors.push(this.HigherVectors(eq1_next_lower_macro))
			
            eq2_next_lower_macro = "".concat(eq1_val,eq2_val+1,eq3_val,eq4_val,eq5_val,eq6_val)
			min_vectors.push(this.HigherVectors(eq2_next_lower_macro))
            
            //eq3 and eq6 are related
            if (eq3==1 && eq6==1){
                //11 --> 21
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val)
				min_vectors.push(this.HigherVectors(eq3eq6_next_lower_macro))
           }
            else if (eq3==0 && eq6==1){
                //01 --> 11
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val) 
 				min_vectors.push(this.HigherVectors(eq3eq6_next_lower_macro))
            }
            else if (eq3==1 && eq6==0){
                //10 --> 11
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val+1) 
 				min_vectors.push(this.HigherVectors(eq3eq6_next_lower_macro))
            }
            else if (eq3==0 && eq6==0){
                //00 --> 01
                //00 --> 10
                eq3eq6_next_lower_macro_left = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val+1)
                eq3eq6_next_lower_macro_right = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val)
 				min_vectors.push(this.HigherVectors(eq3eq6_next_lower_macro_left))
 				min_vectors.push(this.HigherVectors(eq3eq6_next_lower_macro_right))
            }
            else{
                //21 --> 32 (do not exist)
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val+1)
				min_vectors.push(this.HigherVectors(eq3eq6_next_lower_macro))
             }


            eq4_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val+1,eq5_val,eq6_val)
			min_vectors.push(this.HigherVectors(eq4_next_lower_macro))
            eq5_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val+1,eq6_val)
			min_vectors.push(this.HigherVectors(eq4_next_lower_macro))
			
			return min_vectors
 		},
        baseScore() {
            this.cvssMaxVector = null
            if(this.isCheckedWeighted){
                AV_levels={"P": 2.0619,"L": 1.3112,"A": 0.5254,"N": 0}
                PR_levels={"H": 0.4821,"L": 0.1504,"N": 0}
                UI_levels={"A": 0.3296,"P": 0.194,"N": 0}

                AC_levels={"H": 0.3209,"L": 0}
                AT_levels={"P": 0.1865,"N": 0}

                VC_levels={"N": 0.7912,"L": 0.5034,"H": 0}
                VI_levels={"N": 0.8191,"L": 0.4655,"H": 0}
                VA_levels={"N": 0.7333,"L": 0.6045,"H": 0}

                SC_levels={"N": 0.4271,"L": 0.331,"H": 0}
                SI_levels={"N": 0.8717,"L": 0.764,"H": 0.3402,"S": 0}
                SA_levels={"N": 1.0491,"L": 0.9599,"H": 0.5882,"S": 0}


                CR_levels={"L": 0.2321,"M": 0.1342,"H": 0}
                IR_levels={"L": 0.3167,"M": 0.2511,"H": 0}
                AR_levels={"L": 0.3166,"M": 0.1054,"H": 0}

                E_levels={"U": 1.0622,"P": 0.6634,"A": 0}
            }
            else if(this.isCheckedMinimal || this.isCheckedMean){
                AV_levels={"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
                PR_levels={"N": 0.0, "L": 0.1, "H": 0.2}
                UI_levels={"N": 0.0, "P": 0.1, "A": 0.2}

                AC_levels={'L':0.0, 'H':0.1}
                AT_levels={'N':0.0, 'P':0.1}
            
                VC_levels={'H':0.0, 'L':0.1, 'N':0.2}
                VI_levels={'H':0.0, 'L':0.1, 'N':0.2}
                VA_levels={'H':0.0, 'L':0.1, 'N':0.2}    

                SC_levels={'H':0.1, 'L':0.2, 'N':0.3}
                SI_levels={'S':0.0, 'H':0.1, 'L':0.2, 'N':0.3}
                SA_levels={'S':0.0, 'H':0.1, 'L':0.2, 'N':0.3}

                CR_levels={'H':0.0, 'M':0.1, 'L':0.2}
                IR_levels={'H':0.0, 'M':0.1, 'L':0.2}
                AR_levels={'H':0.0, 'M':0.1, 'L':0.2}

                E_levels={'U': 0.2, 'P': 0.1, 'A': 0}

            }

			lookup = this.macroVector
			
            // Exception for no impact on system
            if(lookup.includes("33")) {
                return "0.0"
            }
            value = this.cvssLookupData[lookup]
            if(this.isCheckedMaxValue){
                this.current_value = value
                return value
            }

            qual_value_macrovector = this.getQualScore(value)

            // THIS PART COMPUTE UPPER VECTOR AND LOWER BOUND VECTORS
			
            max_vectors = this.HigherVectors(lookup)
			min_vectors = this.LowerVectors(lookup)
			
            if (max_vectors==undefined){
                alert("Currently disabled")
                return "0.0"
            }

            // mode 2 and 5: hamming distance (0.1 step or weighted)
            for (let i = 0; i < max_vectors.length; i++) {
                tmp_vector = max_vectors[i]
                //cannot have a negative distance if less than max
                hamming_distance_AV = AV_levels[this.m("AV")]-AV_levels[this.extractValueMetric("AV",tmp_vector)]
                hamming_distance_PR = PR_levels[this.m("PR")]-PR_levels[this.extractValueMetric("PR",tmp_vector)]
                hamming_distance_UI = UI_levels[this.m("UI")]-UI_levels[this.extractValueMetric("UI",tmp_vector)]

                hamming_distance_AC = AC_levels[this.m("AC")]-AC_levels[this.extractValueMetric("AC",tmp_vector)]
                hamming_distance_AT = AT_levels[this.m("AT")]-AT_levels[this.extractValueMetric("AT",tmp_vector)]

                hamming_distance_VC = VC_levels[this.m("VC")]-VC_levels[this.extractValueMetric("VC",tmp_vector)]
                hamming_distance_VI = VI_levels[this.m("VI")]-VI_levels[this.extractValueMetric("VI",tmp_vector)]
                hamming_distance_VA = VA_levels[this.m("VA")]-VA_levels[this.extractValueMetric("VA",tmp_vector)]   


                if(this.m("MSI") == "S" && this.m("MSA")=="S"){
                    //use MSI and MSA
                    hamming_distance_SI = SI_levels[this.m("MSI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]             
                    hamming_distance_SA = SA_levels[this.m("MSA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]  
                }
                else if (this.m("MSI") == "S"){
                    //only MSI set to S
                    hamming_distance_SI = SI_levels[this.m("MSI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]
                    hamming_distance_SA = SA_levels[this.m("SA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]
                }
                else if(this.m("MSA") == "S"){
                    //only MSA set to S
                    hamming_distance_SI = SI_levels[this.m("SI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]
                    hamming_distance_SA = SA_levels[this.m("MSA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)] 
                }
                else {
                    //none set to S
                    hamming_distance_SI = SI_levels[this.m("SI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]     
                    hamming_distance_SA = SA_levels[this.m("SA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]  
                }
                hamming_distance_SC = SC_levels[this.m("SC")]-SC_levels[this.extractValueMetric("SC",tmp_vector)]

                hamming_distance_CR = CR_levels[this.m("CR")]-CR_levels[this.extractValueMetric("CR",tmp_vector)]
                hamming_distance_IR = IR_levels[this.m("IR")]-IR_levels[this.extractValueMetric("IR",tmp_vector)]
                hamming_distance_AR = AR_levels[this.m("AR")]-AR_levels[this.extractValueMetric("AR",tmp_vector)]


                //if any is less than zero this is not the right max
                if (hamming_distance_AV<0 || hamming_distance_PR<0 || hamming_distance_UI<0 || hamming_distance_AC<0 || hamming_distance_AT<0 || hamming_distance_VC<0 || hamming_distance_VI<0 || hamming_distance_VA<0 || hamming_distance_SC<0 || hamming_distance_SI<0 || hamming_distance_SA<0 || hamming_distance_CR<0 || hamming_distance_IR<0 || hamming_distance_AR<0) {
                    continue
                }
                else{
                    //if multiple maxes exist to reach it it is enough the first one
                    max_vector = tmp_vector
                    this.cvssMaxVector = max_vector
                    break
                }
            }

			all_min_vectors = []
            for (let i = 0; i < min_vectors_vectors.length; i++) {
                tmp_vector = min_vectors[i]
               //cannot have a positive distance if less than min
                hamming_distance_AV = AV_levels[this.m("AV")]-AV_levels[this.extractValueMetric("AV",tmp_vector)]
                hamming_distance_PR = PR_levels[this.m("PR")]-PR_levels[this.extractValueMetric("PR",tmp_vector)]
                hamming_distance_UI = UI_levels[this.m("UI")]-UI_levels[this.extractValueMetric("UI",tmp_vector)]

                hamming_distance_AC = AC_levels[this.m("AC")]-AC_levels[this.extractValueMetric("AC",tmp_vector)]
                hamming_distance_AT = AT_levels[this.m("AT")]-AT_levels[this.extractValueMetric("AT",tmp_vector)]

                hamming_distance_VC = VC_levels[this.m("VC")]-VC_levels[this.extractValueMetric("VC",tmp_vector)]
                hamming_distance_VI = VI_levels[this.m("VI")]-VI_levels[this.extractValueMetric("VI",tmp_vector)]
                hamming_distance_VA = VA_levels[this.m("VA")]-VA_levels[this.extractValueMetric("VA",tmp_vector)]   


                if(this.m("MSI") == "S" && this.m("MSA")=="S"){
                    //use MSI and MSA
                    hamming_distance_SI = SI_levels[this.m("MSI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]             
                    hamming_distance_SA = SA_levels[this.m("MSA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]  
                }
                else if (this.m("MSI") == "S"){
                    //only MSI set to S
                    hamming_distance_SI = SI_levels[this.m("MSI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]
                    hamming_distance_SA = SA_levels[this.m("SA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]
                }
                else if(this.m("MSA") == "S"){
                    //only MSA set to S
                    hamming_distance_SI = SI_levels[this.m("SI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]
                    hamming_distance_SA = SA_levels[this.m("MSA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)] 
                }
                else {
                    //none set to S
                    hamming_distance_SI = SI_levels[this.m("SI")]-SI_levels[this.extractValueMetric("SI",tmp_vector)]     
                    hamming_distance_SA = SA_levels[this.m("SA")]-SA_levels[this.extractValueMetric("SA",tmp_vector)]  
                }
                hamming_distance_SC = SC_levels[this.m("SC")]-SC_levels[this.extractValueMetric("SC",tmp_vector)]

                hamming_distance_CR = CR_levels[this.m("CR")]-CR_levels[this.extractValueMetric("CR",tmp_vector)]
                hamming_distance_IR = IR_levels[this.m("IR")]-IR_levels[this.extractValueMetric("IR",tmp_vector)]
                hamming_distance_AR = AR_levels[this.m("AR")]-AR_levels[this.extractValueMetric("AR",tmp_vector)]


                //if any is greater than zero this is not the right min
                if (hamming_distance_AV>0 || hamming_distance_PR>0 || hamming_distance_UI>0 || hamming_distance_AC>0 || hamming_distance_AT>0 || hamming_distance_VC>0 || hamming_distance_VI>0 || hamming_distance_VA>0 || hamming_distance_SC>0 || hamming_distance_SI>0 || hamming_distance_SA>0 || hamming_distance_CR>0 || hamming_distance_IR>0 || hamming_distance_AR>0) {
                    continue
                }
                else{
                    //A correct min is found
                    all_min_vectors.push(tmp_vector)
                }
			
			
			// THIS PART TO BE USED FOR MEAN/MAX CALCULATION
			sum_distance = 0;
			for (let i = 0; i < all_min_vectors.length; i++) {
                tmp_vector = min_vectors[i]
				lower_value = this.cvssLookupData[tmp_vector]
				available_distance = this.TotalHammingDistance(max_vector,tmp_vector)
				if (value -  > 0)
					current_distance = this.TotalHammingDistance(max_vector,this.m)	
					sum_distance += value - current_distance/available_distance*(value-lower_value)
			}
			mean_distance = sum_distance/all_min_vectors.length
			
			// THIS PART STILL REQUIRES REFACTORING 
				if(!this.isCheckedMean){
					//setting capped to macrovector
					if(this.isCheckedCappedMacro){

						sum_hamming_distance = 0
                    //consider each eq and its lower macro
                    //no need for EQ5 as hamming is always 0

                    if(current_hamming_distance_eq1>available_distance_eq1){
                        //cap to max changes
                        sum_hamming_distance+=available_distance_eq1
                    }
                    else{
                        //we fall here if either max_change is NaN or because space is enough
                        sum_hamming_distance+=current_hamming_distance_eq1
                    }

                    if(current_hamming_distance_eq2>available_distance_eq2){
                        sum_hamming_distance+=available_distance_eq2
                    }
                    else{
                        sum_hamming_distance+=current_hamming_distance_eq2
                    }

                    if(current_hamming_distance_eq3eq6>available_distance_eq3eq6){
                        sum_hamming_distance+=available_distance_eq3eq6
                    }
                    else{
                        sum_hamming_distance+=current_hamming_distance_eq3eq6
                    }

                    if(current_hamming_distance_eq4>available_distance_eq4){
                        sum_hamming_distance+=available_distance_eq4
                    }
                    else{
                        sum_hamming_distance+=current_hamming_distance_eq4
                    }

                }
                else{
                    //not capped to macrovector, hamming distance is not constrained
                    sum_hamming_distance = hamming_distance_AV + hamming_distance_PR + hamming_distance_UI + hamming_distance_AC + hamming_distance_AT + hamming_distance_VC + hamming_distance_VI + hamming_distance_VA + hamming_distance_SC + hamming_distance_SI + hamming_distance_SA + hamming_distance_CR + hamming_distance_IR + hamming_distance_AR
                }
                value = parseFloat(value) - parseFloat(sum_hamming_distance)
            }
            else{
                step = 0.1
                // mode 3: mean decrement among EQ sets

                //some of them do not exist, we will find them by retrieving the score. If score null then do not exist
                n_existing_lower = 0

                normalized_hamming_eq1 = 0
                normalized_hamming_eq2 = 0
                normalized_hamming_eq3eq6 = 0
                normalized_hamming_eq4 = 0
                normalized_hamming_eq5 = 0

                if (!isNaN(available_distance_eq1)){
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq1_hamming = (current_hamming_distance_eq1)/(this.maxHammingData['eq1'][String(eq1_val)]*step)
                    //can be nan if divided by zero
                    if(isNaN(percent_to_next_eq1_hamming)){
                        percent_to_next_eq1_hamming=0
                    }
                    normalized_hamming_eq1 = available_distance_eq1*percent_to_next_eq1_hamming
                }

                if (!isNaN(available_distance_eq2)){
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq2_hamming = (current_hamming_distance_eq2)/(this.maxHammingData['eq2'][String(eq2_val)]*step)
                    if(isNaN(percent_to_next_eq2_hamming)){
                        percent_to_next_eq2_hamming=0
                    }
                    normalized_hamming_eq2 = available_distance_eq2*percent_to_next_eq2_hamming
                }

                if (!isNaN(available_distance_eq3eq6)){
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq3eq6_hamming = (current_hamming_distance_eq3eq6)/(this.maxHammingData['eq3'][String(eq3_val)][String(eq6_val)]*step)
                    if(isNaN(percent_to_next_eq3eq6_hamming)){
                        percent_to_next_eq3eq6_hamming=0
                    }
                    normalized_hamming_eq3eq6 = available_distance_eq3eq6*percent_to_next_eq3eq6_hamming
                }

                if (!isNaN(available_distance_eq4)){
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq4_hamming = (current_hamming_distance_eq4)/(this.maxHammingData['eq4'][String(eq4_val)]*step)
                    if(isNaN(percent_to_next_eq4_hamming)){
                        percent_to_next_eq4_hamming=0
                    }
                    normalized_hamming_eq4 = available_distance_eq4*percent_to_next_eq4_hamming
                }

                if (!isNaN(available_distance_eq5)){
                    //for eq5 is always 0 the percentage
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq5_hamming = 0
                    normalized_hamming_eq5 = available_distance_eq5*percent_to_next_eq5_hamming
                }

                mean_distance = (normalized_hamming_eq1+normalized_hamming_eq2+normalized_hamming_eq3eq6+normalized_hamming_eq4+normalized_hamming_eq5)/n_existing_lower
                value = parseFloat(value) - parseFloat(mean_distance)
                
            }
                        
            if(value<0){
                value = 0.0
            }

            if(this.isCheckedCappedQualitative){
                qual_value_vector = this.getQualScore(value)
                if (qual_value_macrovector!=qual_value_vector){
                    //cap to qualitative value macrovector score
                    //only lower bound needed
                    if(qual_value_macrovector=="Low"){
                        value = 0.1
                    }
                    else if(qual_value_macrovector=="Medium"){
                        value = 4.0
                    }
                    else if(qual_value_macrovector=="High"){
                        value = 7.0
                    }
                    else if(qual_value_macrovector=="Critical"){
                        value = 9.0
                    }
                }
            }
            this.current_value = value.toFixed(1)
            return value.toFixed(1)
        },
        qualScore() {
            if(this.baseScore == 0) {
                return "None"
            }
            else if(this.baseScore < 4.0) {
                return "Low"
            }
            else if(this.baseScore < 7.0) {
                return "Medium"
            }
            else if(this.baseScore < 9.0) {
                return "High"
            }
            else {
                return "Critical"
            }
        },
    },
 ....
 }
})

app.mount("#app")
