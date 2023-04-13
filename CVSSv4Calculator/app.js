/**
 * Forked from https://github.com/RedHatProductSecurity/cvss-v4-calculator
 * BaseScore algorithm from Fabio Massacci (University of Trento and Vrije Universiteit Amsterdam) and Giorgio Di Tizio (University of Trento)
 * Data for the Weighted Hamming Distance by Ben Edwards (Cyenthia)
 */

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: cvssConfig,
            maxComposedData: maxComposed,
            maxHammingData: maxHamming,
            maxHammingVariableData: maxHammingVariable,
            cvssMacroVectorDetailsData: cvssMacroVectorDetails,
            cvssMacroVectorValuesData: cvssMacroVectorValues,
            showDetails: false,
            cvssSelected: null,
            header_height: 0,
            current_cap: "none",
            isCheckedCappedQualitative: false,
            isCheckedCappedMacro: false,
            current_mode: "minimal",// For later to get rid of the booleans
            isCheckedWeighted: false,
            isCheckedMean: false,
            isCheckedMeanVariable: false,
            isCheckedMaxValue: false,
            isCheckedMinimal: true,
            isClickAdjustDown: true,
            isClickAdjustMiddle: false,
            isClickAdjustUp: false,
            current_adjust: "down", // For later to get rid of booleans
            cvssMaxVector: null,
            max_base_value: 0.0,
            current_value: 0.0,
            currentLookup: "adjusted",
            lookupMap: {
                "base":cvssLookup, 
                "adjusted":cvssLookup_adjusted,
                "linear_clust":cvssLookup_cluster_mean,
                "linear":cvssLookup_linear,
                "rank":cvssLookup_rank_bin,
            }
        }
    },
    methods: {
        getvalueEqLookup(lookup,i){ 
            eq=parseInt(lookup[i])
            eq_val = maxComposed["eq"+String(i+1)][eq]
            return eq_val
        },
        getQualScore(score){
            if(score == 0) {
                return "None"
            }
            else if(score < 4.0) {
                return "Low"
            }
            else if(score < 7.0) {
                return "Medium"
            }
            else if(score < 9.0) {
                return "High"
            }
            else {
                return "Critical"
            }
        },
        extractValueMetric(metric,str){
            //indexOf gives first index of the metric, we then need to go over its size
            extracted = str.slice(str.indexOf(metric) + metric.length + 1)
            //remove what follow
            if(extracted.indexOf('/')>0) {
                metric_val = extracted.substring(0, extracted.indexOf('/'));
            }
            else{
                //case where it is the last metric so no ending /
                metric_val = extracted
            }
            return metric_val
        },
        buttonClass(isPrimary, big=false) {
            result = "btn btn-m"
            if(isPrimary) {
                result += " btn-primary"
            }
            if(!big) {
                result += " btn-sm"
            }

            return result
        },
        baseScoreClass(qualScore) {
            if(qualScore == "Low") {
                return "c-hand text-success"
            }
            else if(qualScore == "Medium") {
                return "c-hand text-warning"
            }
            else if(qualScore == "High") {
                return "c-hand text-error"
            }
            else if(qualScore == "Critical") {
                return "c-hand text-error text-bold"
            }
            else {
                return "c-hand text-gray"
            }
        },
        copyVectorCurrent() {
            navigator.clipboard.writeText(this.vector+','+this.current_value)
            window.location.hash = this.vector
        },
        copyVectorMax() {
            navigator.clipboard.writeText(this.vector+','+this.max_base_value)
            window.location.hash = this.vector
        },
        onButton(metric, value) {
            this.cvssSelected[metric] = value
            window.location.hash = this.vector
        },
        setButtonsToVector(vector) {
            this.resetSelected()
            metrics = vector.split("/")
            for(index in metrics) {
                [key, value] = metrics[index].split(":")
                if(key in this.cvssSelected) {
                    this.cvssSelected[key] = value
                }
            }
        },
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
        onReset() {
            window.location.hash = ""
            this.cvssMaxVector = null
        },
        onChangeModeSelect() {
            this.current_mode = document.getElementById("mode_select").value;
            if (this.current_mode == 'weighted') {
                this.isCheckedWeighted = true;
                this.isCheckedMean = false;
                this.isCheckedMeanVariable = false;
                this.isCheckedMaxValue = false;
                this.isCheckedMinimal = false;
            } else if (this.current_mode == 'mean') {
                console.log("Cap doesn't make sense here")
                document.getElementById("capping_select").value='none';
                this.current_cap = 'none';
                this.isCheckedCappedMacro = false
                this.isCheckedCappedQualitative = false

                this.isCheckedWeighted = false;
                this.isCheckedMean = true;
                this.isCheckedMeanVariable = false;
                this.isCheckedMaxValue = false;
                this.isCheckedMinimal = false;
            } else if (this.current_mode=='mean_variable'){
                console.log("Cap doesn't make sense here")
                document.getElementById("capping_select").value='none';
                this.current_cap = 'none';
                this.isCheckedCappedMacro = false
                this.isCheckedCappedQualitative = false

                this.isCheckedWeighted = false;
                this.isCheckedMean = false;
                this.isCheckedMeanVariable = true;
                this.isCheckedMaxValue = false;
                this.isCheckedMinimal = false;
            } else if (this.current_mode=='max') {
                console.log("Cap doesn't make sense here")
                document.getElementById("capping_select").value='none';
                this.current_cap = 'none';
                this.isCheckedCappedMacro = false
                this.isCheckedCappedQualitative = false

                this.isCheckedWeighted = false;
                this.isCheckedMean = false;
                this.isCheckedMeanVariable = false;
                this.isCheckedMaxValue = true;
                this.isCheckedMinimal = false;
            } else if (this.current_mode=='minimal') {
                this.isCheckedWeighted = false;
                this.isCheckedMean = false;
                this.isCheckedMeanVariable = false;
                this.isCheckedMaxValue = false;
                this.isCheckedMinimal = true;
            }

        },/*
        onClickWeighted() {
            this.isCheckedWeighted = document.getElementById('weighted_checkbox').checked
            if (this.isCheckedWeighted){
                //if true disable mean mode and checkbox
                this.isCheckedMeanVariable = false
                document.getElementById('mean_variable_checkbox').checked = false;

                this.isCheckedMean = false
                document.getElementById('mean_checkbox').checked = false;

                this.isCheckedMaxValue = false
                document.getElementById('max_checkbox').checked = false;

                this.isCheckedMinimal = false
                document.getElementById('minimal_checkbox').checked = false;
   
            }
        },
        onClickMeanVariable() {
            this.isCheckedMeanVariable = document.getElementById('mean_variable_checkbox').checked
            if (this.isCheckedMeanVariable){
                //if true disable mean mode and checkbox
                this.isCheckedMean = false
                document.getElementById('mean_checkbox').checked = false;

                this.isCheckedWeighted = false
                document.getElementById('weighted_checkbox').checked = false;

                this.isCheckedMaxValue = false
                document.getElementById('max_checkbox').checked = false;

                this.isCheckedCappedMacro = false
                document.getElementById('capped_macro_checkbox').checked = false;

                this.isCheckedCappedQualitative = false
                document.getElementById('capped_qual_checkbox').checked = false;

                this.isCheckedMinimal = false
                document.getElementById('minimal_checkbox').checked = false;

            }
        },
        onClickMean() {
            this.isCheckedMean = document.getElementById('mean_checkbox').checked
            if (this.isCheckedMean){
                //if true disable mean mode and checkbox
                this.isCheckedMeanVariable = false
                document.getElementById('mean_variable_checkbox').checked = false;

                this.isCheckedWeighted = false
                document.getElementById('weighted_checkbox').checked = false;

                this.isCheckedMaxValue = false
                document.getElementById('max_checkbox').checked = false;


                this.isCheckedCappedMacro = false
                document.getElementById('capped_macro_checkbox').checked = false;

                this.isCheckedCappedQualitative = false
                document.getElementById('capped_qual_checkbox').checked = false;


                this.isCheckedMinimal = false
                document.getElementById('minimal_checkbox').checked = false;

            }
        },
        onClickMinimal(){
            this.isCheckedMinimal = document.getElementById('minimal_checkbox').checked

            if (this.isCheckedMinimal){
                //if true disable mean mode and checkbox

                this.isCheckedMeanVariable = false
                document.getElementById('mean_variable_checkbox').checked = false;

                this.isCheckedWeighted = false
                document.getElementById('weighted_checkbox').checked = false;

                this.isCheckedMaxValue = false
                document.getElementById('max_checkbox').checked = false;   

                this.isCheckedMean = false
                document.getElementById('mean_checkbox').checked = false;

                this.isCheckedCappedMacro = false
                document.getElementById('capped_macro_checkbox').checked = false;

                this.isCheckedCappedQualitative = false
                document.getElementById('capped_qual_checkbox').checked = false;
            }
        },
        onClickMaxValue(){
            this.isCheckedMaxValue = document.getElementById('max_checkbox').checked
            if (this.isCheckedMaxValue){
                //disable other
                this.isCheckedMeanVariable = false
                document.getElementById('mean_variable_checkbox').checked = false;

                this.isCheckedWeighted = false
                document.getElementById('weighted_checkbox').checked = false;

                this.isCheckedMean = false
                document.getElementById('mean_checkbox').checked = false;


                this.isCheckedMinimal = false
                document.getElementById('minimal_checkbox').checked = false;

                this.isCheckedCappedMacro = false
                document.getElementById('capped_macro_checkbox').checked = false;

                this.isCheckedCappedQualitative = false
                document.getElementById('capped_qual_checkbox').checked = false;

            }
        },*/
        onChangeDataSelect() {
            this.currentLookup = document.getElementById("dataset_select").value;
        },
        onAdjustmentSelect() {
            this.current_adjust = document.getElementById("adjustment_mode_select").value;
            if (this.current_adjust=='up') {
                this.isClickAdjustUp = true;
                this.isClickAdjustMiddle = false;
                this.isClickAdjustDown = false;
            } else if  (this.current_adjust=='middle') {
                this.isClickAdjustUp = false;
                this.isClickAdjustMiddle = true;
                this.isClickAdjustDown = false;
            } else if (this.current_adjust=='down') {
                this.isClickAdjustUp = false;
                this.isClickAdjustMiddle = false;
                this.isClickAdjustDown = true;
            }
        },
        onCappingChange() {
            this.current_cap = document.getElementById("capping_select");
            if (this.current_cap == 'qual') {
                if (['mean', 'mean_variable', 'max'].includes(this.current_mode)) {
                    console.log("Cap doesn't make sense here")
                    document.getElementById("capping_select").value='none';
                    this.current_cap = 'none';
                    this.isCheckedCappedMacro = false;
                    this.isCheckedCappedQualitative = false;
                } else {
                  this.isCheckedCappedMacro = false;
                  this.isCheckedCappedQualitative = true;
                }
            } else if (this.current_cap == 'macro') {
                if (['mean', 'mean_variable', 'max'].includes(this.current_mode)) {
                    console.log("Cap doesn't make sense here")
                    document.getElementById("capping_select").value='none';
                    this.current_cap = 'none';
                    this.isCheckedCappedMacro = false;
                    this.isCheckedCappedQualitative = false;
                } else {
                  this.isCheckedCappedMacro = true;
                  this.isCheckedCappedQualitative = false;
                }
            } else if (this.current_cap=='none') {
                this.isCheckedCappedMacro = false;
                this.isCheckedCappedQualitative = false;
            }


        }, 
        /*onClickCappedQualitative() {
            this.isCheckedCappedQualitative = document.getElementById('capped_qual_checkbox').checked
            if (this.isCheckedCappedQualitative){
                //if true disable mean mode and checkbox
                this.isCheckedMeanVariable = false
                document.getElementById('mean_variable_checkbox').checked = false;

                this.isCheckedMean = false
                document.getElementById('mean_checkbox').checked = false;

                this.isCheckedCappedMacro = false
                document.getElementById('capped_macro_checkbox').checked = false;
            }
        },
        onClickCappedMacro() {
            this.isCheckedCappedMacro = document.getElementById('capped_macro_checkbox').checked
            if (this.isCheckedCappedMacro){
                //if true disable mean mode and checkbox
                this.isCheckedMeanVariable = false
                document.getElementById('mean_variable_checkbox').checked = false;

                this.isCheckedMean = false
                document.getElementById('mean_checkbox').checked = false;

                this.isCheckedCappedQualitative = false
                document.getElementById('capped_qual_checkbox').checked = false;
            }
        },*/
        resetSelected() {
            this.cvssSelected = {}
            for([metricType, metricTypeData] of Object.entries(this.cvssConfigData)) {
                for([metricGroup, metricGroupData] of Object.entries(metricTypeData.metric_groups)) {
                    for([metric, metricData] of Object.entries(metricGroupData)) {
                        this.cvssSelected[metricData.short] = metricData.selected
                    }
                }
            }
        },
        splitObjectEntries(object, chunkSize) {
            arr = Object.entries(object)
            res = [];
            for(let i = 0; i < arr.length; i += chunkSize) {
                chunk = arr.slice(i, i + chunkSize)
                res.push(chunk)
            }
            return res
        }
    },
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
            this.max_base_value = this.lookupMap[this.currentLookup][lookup]
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
        baseScore() {
            //define lookup table
            lookuptable = this.lookupMap[this.currentLookup];

            this.cvssMaxVector = null
            if((this.isCheckedWeighted || this.isCheckedMeanVariable) && !(this.isCheckedMean) && !(this.isCheckedMinimal)){
                //console.log("Variable values")
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
            value = lookuptable[lookup]
            if(this.isCheckedMaxValue){
                this.current_value = value
                return value
            }

            qual_value_macrovector = this.getQualScore(value)

            eq1_val = parseInt(lookup[0])
            eq2_val = parseInt(lookup[1])
            eq3_val = parseInt(lookup[2])
            eq4_val = parseInt(lookup[3])
            eq5_val = parseInt(lookup[4])
            eq6_val = parseInt(lookup[5])

            //compute next lower macro, it can also not exist
            eq1_next_lower_macro = "".concat(eq1_val+1,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val)
            eq2_next_lower_macro = "".concat(eq1_val,eq2_val+1,eq3_val,eq4_val,eq5_val,eq6_val)

            eq1_next_higher_macro = "".concat(eq1_val-1,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val)
            eq2_next_higher_macro = "".concat(eq1_val,eq2_val-1,eq3_val,eq4_val,eq5_val,eq6_val)
            
            //eq3 and eq6 are related
            if (eq3==1 && eq6==1){
                //11 --> 21
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val)
            }
            else if (eq3==0 && eq6==1){
                //01 --> 11
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val) 
            }
            else if (eq3==1 && eq6==0){
                //10 --> 11
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val+1) 
            }
            else if (eq3==0 && eq6==0){
                //00 --> 01
                //00 --> 10
                eq3eq6_next_lower_macro_left = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val+1)
                eq3eq6_next_lower_macro_right = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val)
            }
            else{
                //21 --> 32 (do not exist)
                eq3eq6_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val+1)
            }


            eq4_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val+1,eq5_val,eq6_val)
            eq5_next_lower_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val+1,eq6_val)

            if (eq3==0 && eq6==0){
                //00 --> does not exist
                eq3eq6_next_higher_macro = "".concat(eq1_val,eq2_val,eq3_val-1,eq4_val,eq5_val,eq6_val-1)
            }
            else if (eq3==0 && eq6==1){
                //01 --> 00
                eq3eq6_next_higher_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val-1) 
            }
            else if (eq3==1 && eq6==0){
                //10 --> 00
                eq3eq6_next_higher_macro = "".concat(eq1_val,eq2_val,eq3_val-1,eq4_val,eq5_val,eq6_val) 
            }
            else if (eq3==1 && eq6==1){
                //11 --> 10
                //11 --> 01
                eq3eq6_next_higher_macro_left = "".concat(eq1_val,eq2_val,eq3_val-1,eq4_val,eq5_val,eq6_val) 
                eq3eq6_next_higher_macro_right = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val-1) 
            }
            else if (eq3==2 && eq6==0){
                //20 does not exist so we'll set it so it gets us nonsense
                eq3eq6_next_higher_macro = "".concat(eq1_val,eq2_val,eq3_val-1,eq4_val,eq5_val,eq6_val-1) 
            }
            else if (eq3==2 && eq6==1){
                //21 --> 11 has to go to 11 as 20 doesn't exist
                eq3eq6_next_higher_macro = "".concat(eq1_val,eq2_val,eq3_val-1,eq4_val,eq5_val,eq6_val) 
            }

            eq4_next_higher_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val-1,eq5_val,eq6_val)
            eq5_next_higher_macro = "".concat(eq1_val,eq2_val,eq3_val,eq4_val,eq5_val-1,eq6_val)

            //get their score, if the next lower macro score do not exist the result is NaN
            score_eq1_next_lower_macro = lookuptable[eq1_next_lower_macro]
            score_eq2_next_lower_macro = lookuptable[eq2_next_lower_macro]

            score_eq1_next_higher_macro = lookuptable[eq1_next_higher_macro]
            score_eq2_next_higher_macro = lookuptable[eq2_next_higher_macro]


            if (eq3==0 && eq6==0){
                //multiple path take the one with higher score
                score_eq3eq6_next_lower_macro_left = lookuptable[eq3eq6_next_lower_macro_left]
                score_eq3eq6_next_lower_macro_right = lookuptable[eq3eq6_next_lower_macro_right]

                if (score_eq3eq6_next_lower_macro_left>score_eq3eq6_next_lower_macro_right){
                    score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left
                }
                else{
                    score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right
                }
            }
            else{
                score_eq3eq6_next_lower_macro = lookuptable[eq3eq6_next_lower_macro]
            }

            if (eq3==1 && eq6==1){
                //multiple path take the one with lower score
                score_eq3eq6_next_higher_macro_left = lookuptable[eq3eq6_next_higher_macro_left]
                score_eq3eq6_next_higher_macro_right = lookuptable[eq3eq6_next_higher_macro_right]

                if (score_eq3eq6_next_higher_macro_left < score_eq3eq6_next_higher_macro_right){
                    score_eq3eq6_next_higher_macro = score_eq3eq6_next_higher_macro_left
                }
                else{
                    score_eq3eq6_next_higher_macro = score_eq3eq6_next_higher_macro_right
                }
            }
            else{
                score_eq3eq6_next_higher_macro = lookuptable[eq3eq6_next_higher_macro]
            }


            score_eq4_next_lower_macro = lookuptable[eq4_next_lower_macro]
            score_eq5_next_lower_macro = lookuptable[eq5_next_lower_macro]

            score_eq4_next_higher_macro = lookuptable[eq4_next_higher_macro]
            score_eq5_next_higher_macro = lookuptable[eq5_next_higher_macro]

            //get all max vector for the eq
            eq1_maxes = this.getvalueEqLookup(lookup,0)
            eq2_maxes = this.getvalueEqLookup(lookup,1)
            eq3_eq6_maxes = this.getvalueEqLookup(lookup,2)[lookup[5]]
            eq4_maxes = this.getvalueEqLookup(lookup,3)
            eq5_maxes = this.getvalueEqLookup(lookup,4)

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

            

            current_hamming_distance_eq1 = hamming_distance_AV + hamming_distance_PR + hamming_distance_UI
            current_hamming_distance_eq2 = hamming_distance_AC + hamming_distance_AT
            current_hamming_distance_eq3eq6 = hamming_distance_VC + hamming_distance_VI + hamming_distance_VA + hamming_distance_CR + hamming_distance_IR + hamming_distance_AR
            current_hamming_distance_eq4 = hamming_distance_SC + hamming_distance_SI + hamming_distance_SA
            current_hamming_distance_eq5 = 0
            
            if((this.isCheckedWeighted || this.isCheckedMeanVariable) && !(this.isCheckedMean) && !(this.isCheckedMinimal)){
                maxHamming_eq1 = this.maxHammingVariableData['eq1'][String(eq1_val)]
                maxHamming_eq2 = this.maxHammingVariableData['eq2'][String(eq2_val)]
                maxHamming_eq3eq6 = this.maxHammingVariableData['eq3'][String(eq3_val)][String(eq6_val)]
                maxHamming_eq4 = this.maxHammingVariableData['eq4'][String(eq4_val)]
            } else {
                maxHamming_eq1 = this.maxHammingData['eq1'][String(eq1_val)]*0.1
                maxHamming_eq2 = this.maxHammingData['eq2'][String(eq2_val)]*0.1
                maxHamming_eq3eq6 = this.maxHammingData['eq3'][String(eq3_val)][String(eq6_val)]*0.1
                maxHamming_eq4 = this.maxHammingData['eq4'][String(eq4_val)]*0.1
            }

            //if the next lower macro score do not exist the result is Nan
            if (this.isClickAdjustDown) {
                available_distance_eq1 = value - score_eq1_next_lower_macro
                available_distance_eq2 = value - score_eq2_next_lower_macro
                available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro
                available_distance_eq4 = value - score_eq4_next_lower_macro
                available_distance_eq5 = value - score_eq5_next_lower_macro
            } else if (this.isClickAdjustUp) {
                available_distance_eq1 = score_eq1_next_higher_macro - value;
                available_distance_eq2 = score_eq2_next_higher_macro - value;
                available_distance_eq3eq6 = score_eq3eq6_next_higher_macro - value;
                available_distance_eq4 = score_eq4_next_higher_macro - value;
                available_distance_eq5 =  score_eq5_next_higher_macro - value;
            } else {
                //Down further than halfway, so increase
                if (current_hamming_distance_eq1 > maxHamming_eq1/2){
                    available_distance_eq1 = (value - score_eq1_next_lower_macro)/2;
                } else { 
                    available_distance_eq1 = (score_eq1_next_higher_macro - value)/2;
                }

                if (current_hamming_distance_eq2 > maxHamming_eq2/2){
                    available_distance_eq2 = (value - score_eq2_next_lower_macro)/2;
                } else {
                    available_distance_eq2 = (score_eq2_next_higher_macro - value)/2;
                }
                if (current_hamming_distance_eq3eq6 > maxHamming_eq3eq6/2){
                    available_distance_eq3eq6 = (value - score_eq3eq6_next_lower_macro)/2;
                } else {
                    available_distance_eq3eq6 = (score_eq3eq6_next_higher_macro - value)/2;
                }
                if (current_hamming_distance_eq4 > maxHamming_eq4/2){
                    available_distance_eq4 = (value - score_eq4_next_lower_macro)/2;
                } else {
                    available_distance_eq4 = (score_eq4_next_higher_macro - value)/2;
                }
            }

            
            if (this.isClickAdjustUp) {                
                current_hamming_distance_eq1 =  current_hamming_distance_eq1 - maxHamming_eq1 
                current_hamming_distance_eq2 =  current_hamming_distance_eq2 - maxHamming_eq2
                current_hamming_distance_eq3eq6 = current_hamming_distance_eq3eq6 - maxHamming_eq3eq6 
                current_hamming_distance_eq4 =  current_hamming_distance_eq4 - maxHamming_eq4
            } else if(this.isClickAdjustMiddle) {
                current_hamming_distance_eq1 =  current_hamming_distance_eq1 - maxHamming_eq1/2 
                current_hamming_distance_eq2 =  current_hamming_distance_eq2 - maxHamming_eq2/2
                current_hamming_distance_eq3eq6 = current_hamming_distance_eq3eq6 - maxHamming_eq3eq6/2
                current_hamming_distance_eq4 =  current_hamming_distance_eq4 - maxHamming_eq4/2
            }
            percent_to_next_eq1_hamming = 0
            percent_to_next_eq2_hamming = 0
            percent_to_next_eq3eq6_hamming = 0
            percent_to_next_eq4_hamming = 0
            percent_to_next_eq5_hamming = 0
            
            if(!this.isCheckedMean && !this.isCheckedMeanVariable){
                //setting capped to macrovector
                if(this.isCheckedCappedMacro){

                    sum_hamming_distance = 0
                    //consider each eq and its lower macro
                    //no need for EQ5 as hamming is always 0

                    if(Math.abs(current_hamming_distance_eq1)>available_distance_eq1){
                        //cap to max changes
                        sum_hamming_distance+=available_distance_eq1*Math.sign(current_hamming_distance_eq1);
                    }
                    else{
                        //we fall here if either max_change is NaN or because space is enough
                        sum_hamming_distance+=current_hamming_distance_eq1
                    }

                    if(Math.abs(current_hamming_distance_eq2)>available_distance_eq2){
                        sum_hamming_distance+=available_distance_eq2*Math.sign(current_hamming_distance_eq2)
                    }
                    else{
                        sum_hamming_distance+=current_hamming_distance_eq2
                    }

                    if(Math.abs(current_hamming_distance_eq3eq6)>available_distance_eq3eq6){
                        sum_hamming_distance+=available_distance_eq3eq6*Math.sign(current_hamming_distance_eq3eq6)
                    }
                    else{
                        sum_hamming_distance+=current_hamming_distance_eq3eq6
                    }

                    if(Math.abs(current_hamming_distance_eq4)>available_distance_eq4){
                        sum_hamming_distance+=available_distance_eq4
                    }
                    else{
                        sum_hamming_distance+=current_hamming_distance_eq4*Math.sign(current_hamming_distance_eq4)
                    }

                }
                else{
                    //not capped to macrovector, hamming distance is not constrained
                    //sum_hamming_distance = hamming_distance_AV + hamming_distance_PR + hamming_distance_UI + hamming_distance_AC + hamming_distance_AT + hamming_distance_VC + hamming_distance_VI + hamming_distance_VA + hamming_distance_SC + hamming_distance_SI + hamming_distance_SA + hamming_distance_CR + hamming_distance_IR + hamming_distance_AR
                    sum_hamming_distance = current_hamming_distance_eq1 + current_hamming_distance_eq2 + current_hamming_distance_eq3eq6 + current_hamming_distance_eq4;
                }
                value = parseFloat(value) - parseFloat(sum_hamming_distance)
            }
            else{
                //console.log("MEAN SECTION")
                step = 0.1
                // mode 3: mean decrement among EQ sets

                //some of them do not exist, we will find them by retrieving the score. If score null then do not exist
                n_existing_lower = 0

                normalized_hamming_eq1 = 0
                normalized_hamming_eq2 = 0
                normalized_hamming_eq3eq6 = 0
                normalized_hamming_eq4 = 0
                normalized_hamming_eq5 = 0

                if(this.isCheckedMeanVariable){
                    //console.log("Variable MEAN")
                    //adjust size to avoid 100% coverage using available distance
                    if(available_distance_eq1>0.1){
                        available_distance_eq1 = available_distance_eq1 - step
                    }
                    if(available_distance_eq2>0.1){
                        available_distance_eq2 = available_distance_eq2 - step
                    }
                    if(available_distance_eq3eq6>0.1){
                        available_distance_eq3eq6 = available_distance_eq3eq6 - step

                    }
                    if(available_distance_eq4>0.1){
                        available_distance_eq4 = available_distance_eq4 - step
                    }

                    maxHamming_eq1 = this.maxHammingVariableData['eq1'][String(eq1_val)]
                    maxHamming_eq2 = this.maxHammingVariableData['eq2'][String(eq2_val)]
                    maxHamming_eq3eq6 = this.maxHammingVariableData['eq3'][String(eq3_val)][String(eq6_val)]
                    maxHamming_eq4 = this.maxHammingVariableData['eq4'][String(eq4_val)]
                }
                else{
                    //here adjustment is not neeeded as the hamming distance already include the space
                    //case 0.1 step, multiply by step because distance is pure
                    maxHamming_eq1 = this.maxHammingData['eq1'][String(eq1_val)]*step
                    maxHamming_eq2 = this.maxHammingData['eq2'][String(eq2_val)]*step
                    maxHamming_eq3eq6 = this.maxHammingData['eq3'][String(eq3_val)][String(eq6_val)]*step
                    maxHamming_eq4 = this.maxHammingData['eq4'][String(eq4_val)]*step
                }

                if (this.isClickAdjustMiddle) {
                    maxHamming_eq1 = maxHamming_eq1/2
                    maxHamming_eq2 = maxHamming_eq2/2
                    maxHamming_eq3eq6 = maxHamming_eq3eq6/2
                    maxHamming_eq4 = maxHamming_eq4/2
                }

                if (!isNaN(available_distance_eq1)){
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq1_hamming = (current_hamming_distance_eq1)/maxHamming_eq1
                    //can be nan if divided by zero
                    if(isNaN(percent_to_next_eq1_hamming)){
                        percent_to_next_eq1_hamming=0
                    }
                    
                    normalized_hamming_eq1 = available_distance_eq1*percent_to_next_eq1_hamming
                    
                }

                if (!isNaN(available_distance_eq2)){
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq2_hamming = (current_hamming_distance_eq2)/maxHamming_eq2
                    if(isNaN(percent_to_next_eq2_hamming)){
                        percent_to_next_eq2_hamming=0
                    }
                    
                    normalized_hamming_eq2 = available_distance_eq2*percent_to_next_eq2_hamming
                }

                if (!isNaN(available_distance_eq3eq6)){
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq3eq6_hamming = (current_hamming_distance_eq3eq6)/maxHamming_eq3eq6
                    if(isNaN(percent_to_next_eq3eq6_hamming)){
                        percent_to_next_eq3eq6_hamming=0
                    }
                    
                    normalized_hamming_eq3eq6 = available_distance_eq3eq6*percent_to_next_eq3eq6_hamming
                }

                if (!isNaN(available_distance_eq4)){
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq4_hamming = (current_hamming_distance_eq4)/maxHamming_eq4
                    if(isNaN(percent_to_next_eq4_hamming)){
                        percent_to_next_eq4_hamming=0
                    }
                    
                    normalized_hamming_eq4 = available_distance_eq4*percent_to_next_eq4_hamming
                }

                if (!isNaN(available_distance_eq5)){
                    //for eq5 is always 0 the percentage
                    n_existing_lower=n_existing_lower+1
                    percent_to_next_eq5_hamming = 0
                    if(isNaN(percent_to_next_eq5_hamming)){
                        percent_to_next_eq5_hamming=0
                    }
                    
                    normalized_hamming_eq5 = available_distance_eq5*percent_to_next_eq5_hamming
                }
                //console.log("#############")
                if (n_existing_lower==0) {
                    mean_distance = 0
                } else { //sometimes we need to go up but there is nothing there, or down but there is nothing there so it's a change of 0.
                    mean_distance = (normalized_hamming_eq1+normalized_hamming_eq2+normalized_hamming_eq3eq6+normalized_hamming_eq4+normalized_hamming_eq5)/n_existing_lower
                }
                //console.log(n_existing_lower)
                //console.log(mean_distance)
                value = parseFloat(value) - parseFloat(mean_distance);

            }
            
                        
            if(value<0){
                value = 0.0
            }

            if(value>10){
                value = 10.0
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
    beforeMount() {
        this.resetSelected()
    },
    mounted() {
        this.setButtonsToVector(window.location.hash)
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash)
        })

        const resizeObserver = new ResizeObserver(() => {
            //console.log("Size changed")
            this.header_height = document.getElementById('header').clientHeight
        })

        resizeObserver.observe(document.getElementById('header'))
    }
})

app.mount("#app")
