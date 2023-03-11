const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: cvssConfig,
            cvssLookupData: cvssLookup,
            maxLookupData: maxLookup,
            cvssMacroVectorDetailsData: cvssMacroVectorDetails,
            cvssMacroVectorValuesData: cvssMacroVectorValues,
            showDetails: false,
            cvssSelected: null,
            header_height: 0
        }
    },
    methods: {
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
        copyVector() {
            navigator.clipboard.writeText(this.vector)
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

            // The three security requirements metrics have X equivalent to M.
            // CR:X is the same as CR:M
            if(metric == "CR" && selected == "X") {
                return "M"
            }
            // IR:X is the same as IR:M
            if(metric == "IR" && selected == "X") {
                return "M"
            }
            // AR:X is the same as AR:M
            if(metric == "AR" && selected == "X") {
                return "M"
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
        },
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
            AV_levels={"N": 0, "A": 1, "L": 2, "P": 3}
            PR_levels={"N": 0, "L": 1, "H": 2}
            UI_levels={"N": 0, "P": 1, "A": 2}

            AC_levels={'L':0, 'H':1}
            AT_levels={'N':0, 'P':1}
        
            VC_levels={'H':0, 'L':1, 'N':2}
            VI_levels={'H':0, 'L':1, 'N':2}
            VA_levels={'H':0, 'L':1, 'N':2}    

            SC_levels={'H':1, 'L':2, 'N':3}
            SI_levels={'S':0, 'H':1, 'L':2, 'N':3}
            SA_levels={'S':0, 'H':1, 'L':2, 'N':3}

            step = 0.1
            lookup = this.macroVector
            // Exception for no impact on system
            if(lookup.includes("33")) {
                return "0.0"
            }
            value = this.cvssLookupData[lookup]
            //get the configuration of the max
            max_vectors = this.maxLookupData[lookup]
            if (max_vectors==undefined){
                alert("Currently disabled")
                return "0.0"
            }

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

   
                console.log(hamming_distance_SC)
                console.log(hamming_distance_SI)
                console.log(hamming_distance_SA)
   

                //if any is less than zero this is not the right max
                if (hamming_distance_AV<0 || hamming_distance_PR<0 || hamming_distance_UI<0 || hamming_distance_AC<0 || hamming_distance_AT<0 || hamming_distance_VC<0 || hamming_distance_VI<0 || hamming_distance_VA<0 || hamming_distance_SC<0 || hamming_distance_SI<0 || hamming_distance_SA<0) {
                    continue
                }
                else{
                    //if multiple maxes exist to reach it it is enough the first one
                    max_vector = tmp_vector
                    break
                }
            }
            console.log(tmp_vector)


            sum_hamming_distance = hamming_distance_AV + hamming_distance_PR + hamming_distance_UI + hamming_distance_AC + hamming_distance_AT + hamming_distance_VC + hamming_distance_VI + hamming_distance_VA + hamming_distance_SC + hamming_distance_SI + hamming_distance_SA

            value = parseFloat(value) - parseFloat(step*sum_hamming_distance)

            // TODO: Do not use floats
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
            console.log("Size changed")
            this.header_height = document.getElementById('header').clientHeight
        })

        resizeObserver.observe(document.getElementById('header'))
    }
})

app.mount("#app")