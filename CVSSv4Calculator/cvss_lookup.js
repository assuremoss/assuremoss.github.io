/**
 * Forked from https://github.com/RedHatProductSecurity/cvss-v4-calculator
 * Table created by Giorgio Di Tizio (University of Trento) from data by Ben Edwards (Cyenthia), Peter Mell (NIST)
 */

cvssLookup = {
"000000":"10",
 "000001":"10",
 "000100":"10",
 "000101":"10",
 "010000":"9.9",
 "000010":"9.8",
 "001000":"9.8",
 "100000":"9.8",
 "010001":"9.7",
 "011000":"9.7",
 "001010":"9.6",
 "010010":"9.6",
 "010100":"9.6",
 "000011":"9.5",
 "000020":"9.5",
 "001001":"9.5",
 "100001":"9.5",
 "110000":"9.5",
 "000110":"9.4",
 "100010":"9.4",
 "100100":"9.4",
 "101000":"9.4",
 "000200":"9.3",
 "001100":"9.3",
 "002001":"9.3",
 "010020":"9.3",
 "011001":"9.3",
 "200000":"9.3",
 "000021":"9.2",
 "000201":"9.2",
 "010011":"9.2",
 "010200":"9.2",
 "011010":"9.2",
 "011100":"9.2",
 "000120":"9.1",
 "001011":"9.1",
 "010101":"9.1",
 "000210":"9",
 "001020":"9",
 "001101":"9",
 "010110":"9",
 "100020":"9",
 "110001":"9",
 "110100":"9",
 "001110":"8.9",
 "001200":"8.9",
 "012001":"8.9",
 "100101":"8.9",
 "200001":"8.9",
 "101001":"8.8",
 "101010":"8.8",
 "111000":"8.8",
 "000111":"8.7",
 "100200":"8.7",
 "110010":"8.7",
 "210000":"8.7",
 "011020":"8.6",
 "200010":"8.6",
 "200100":"8.6",
 "001021":"8.5",
 "010021":"8.5",
 "011011":"8.5",
 "011200":"8.5",
 "100011":"8.5",
 "100110":"8.5",
 "102001":"8.5",
 "201000":"8.5",
 "002011":"8.4",
 "010120":"8.4",
 "101100":"8.4",
 "001120":"8.3",
 "002101":"8.3",
 "010111":"8.3",
 "010201":"8.2",
 "010210":"8.2",
 "000121":"8.1",
 "000220":"8.1",
 "001111":"8.1",
 "011101":"8.1",
 "001201":"8",
 "011110":"8",
 "100021":"8",
 "000211":"7.9",
 "001210":"7.9",
 "012011":"7.8",
 "200020":"7.8",
 "100120":"7.7",
 "101101":"7.7",
 "110020":"7.7",
 "110200":"7.7",
 "111001":"7.7",
 "111010":"7.7",
 "211000":"7.7",
 "002021":"7.6",
 "101011":"7.6",
 "101020":"7.6",
 "110101":"7.6",
 "210001":"7.6",
 "100201":"7.5",
 "110110":"7.5",
 "111100":"7.5",
 "201001":"7.5",
 "201010":"7.5",
 "100210":"7.4",
 "101110":"7.4",
 "110011":"7.4",
 "112001":"7.4",
 "200101":"7.4",
 "200110":"7.4",
 "210010":"7.4",
 "010220":"7.3",
 "011021":"7.3",
 "100111":"7.3",
 "201100":"7.3",
 "102011":"7.2",
 "202001":"7.2",
 "210100":"7.2",
 "011111":"7.1",
 "012101":"7.1",
 "101200":"7.1",
 "200011":"7.1",
 "002111":"7",
 "010121":"7",
 "010211":"7",
 "011120":"7",
 "011201":"7",
 "011210":"7",
 "110021":"7",
 "200200":"7",
 "002201":"6.9",
 "001220":"6.8",
 "110210":"6.8",
 "001211":"6.7",
 "101021":"6.7",
 "000221":"6.6",
 "001121":"6.6",
 "110201":"6.6",
 "111011":"6.6",
 "210020":"6.6",
 "102101":"6.5",
 "100220":"6.4",
 "201020":"6.3",
 "100211":"6.2",
 "211100":"6.1",
 "111200":"6",
 "110111":"5.9",
 "101210":"5.8",
 "111101":"5.8",
 "200120":"5.8",
 "101201":"5.7",
 "201101":"5.7",
 "211001":"5.6",
 "012021":"5.5",
 "111020":"5.4",
 "211010":"5.4",
 "101120":"5.3",
 "210011":"5.3",
 "200021":"5.2",
 "210101":"5.2",
 "010221":"5.1",
 "011211":"5.1",
 "101111":"5.1",
 "111110":"5.1",
 "201011":"5.1",
 "012111":"5",
 "200210":"5",
 "100121":"4.9",
 "110120":"4.9",
 "001221":"4.8",
 "210200":"4.8",
 "201110":"4.7",
 "102021":"4.6",
 "210110":"4.6",
 "200201":"4.5",
 "002121":"4.4",
 "112011":"4.4",
 "200111":"4.4",
 "011220":"4.3",
 "201200":"4.3",
 "002211":"4.2",
 "110220":"4.1",
 "211020":"4.1",
 "011121":"4",
 "012201":"3.9",
 "212001":"3.9",
 "110211":"3.8",
 "111021":"3.8",
 "202101":"3.8",
 "100221":"3.7",
 "102111":"3.7",
 "112021":"3.7",
 "112101":"3.7",
 "111120":"3.6",
 "111201":"3.6",
 "200220":"3.6",
 "102201":"3.5",
 "111210":"3.5",
 "211011":"3.5",
 "202011":"3.4",
 "101121":"3.3",
 "101220":"3.3",
 "111111":"3.3",
 "210021":"3.3",
 "101211":"3.2",
 "200211":"3.2",
 "210201":"3.2",
 "110121":"3.1",
 "201120":"3.1",
 "201201":"3.1",
 "210120":"3.1",
 "210210":"3.1",
 "012121":"3",
 "012211":"3",
 "201021":"3",
 "210111":"3",
 "211200":"3",
 "211110":"2.9",
 "200121":"2.8",
 "201210":"2.8",
 "211101":"2.8",
 "011221":"2.7",
 "102121":"2.7",
 "212101":"2.7",
 "002221":"2.6",
 "212011":"2.6",
 "110221":"2.5",
 "201111":"2.5",
 "202201":"2.4",
 "111211":"2.3",
 "112111":"2.3",
 "112201":"2.2",
 "101221":"2.1",
 "111220":"2.1",
 "200221":"2",
 "202021":"2",
 "210211":"2",
 "111121":"1.9",
 "202111":"1.9",
 "211120":"1.8",
 "102211":"1.7",
 "201220":"1.7",
 "210220":"1.7",
 "211021":"1.7",
 "012221":"1.6",
 "201121":"1.6",
 "201211":"1.6",
 "210121":"1.6",
 "211201":"1.6",
 "211210":"1.5",
 "211111":"1.4",
 "212021":"1.4",
 "111221":"1.3",
 "112121":"1.3",
 "102221":"1.2",
 "112211":"1.2",
 "212111":"1.2",
 "202121":"1.1",
 "212201":"1.1",
 "202211":"1",
 "210221":"0.9",
 "211121":"0.9",
 "211220":"0.9",
 "201221":"0.8",
 "211211":"0.7",
 "112221":"0.6",
 "212121":"0.5",
 "202221":"0.4",
 "212211":"0.3",
 "211221":"0.2",
 "212221":"0.1"
 }

cvssLookup_adjusted_global = {
"000000":"10",
"000001":"10",
"000100":"10",
"000101":"10",
"010000":"9.9",
"000010":"9.8",
"001000":"9.8",
"100000":"9.8",
"010001":"9.7",
"011000":"9.7",
"001010":"9.6",
"010010":"9.6",
"010100":"9.6",
"000011":"9.5",
"000020":"9.5",
"001001":"9.5",
"100001":"9.5",
"110000":"9.5",
"000110":"9.4",
"100010":"9.4",
"100100":"9.4",
"101000":"9.4",
"000200":"9.3",
"001100":"9.3",
"002001":"9.3",
"010020":"9.3",
"011001":"9.3",
"200000":"9.3",
"000021":"9.2",
"000201":"9.2",
"010011":"9.2",
"010200":"9.2",
"011010":"9.2",
"011100":"9.2",
"000120":"9.1",
"001011":"9.1",
"010101":"9.1",
"000210":"9",
"001020":"9",
"001101":"9",
"010110":"9",
"100020":"9",
"110001":"9",
"110100":"9",
"001110":"8.9",
"001200":"8.9",
"012001":"8.9",
"100101":"8.9",
"200001":"8.9",
"101001":"8.8",
"101010":"8.8",
"111000":"8.8",
"000111":"8.7",
"100200":"8.7",
"110010":"8.7",
"210000":"8.7",
"011020":"8.6",
"200010":"8.6",
"200100":"8.6",
"001021":"8.5",
"010021":"8.5",
"011011":"8.5",
"011200":"8.5",
"100011":"8.5",
"100110":"8.5",
"102001":"8.5",
"201000":"8.5",
"002011":"8.4",
"010120":"8.4",
"101100":"8.4",
"001120":"8.3",
"002101":"8.3",
"010111":"8.3",
"010201":"8.2",
"010210":"8.2",
"000121":"8.1",
"000220":"8.1",
"001111":"8.1",
"011101":"8.1",
"001201":"8",
"011110":"8",
"100021":"8",
"000211":"7.9",
"001210":"7.9",
"012011":"7.8",
"200020":"7.8",
"100120":"7.7",
"101101":"7.7",
"110020":"7.7",
"110200":"7.7",
"111001":"7.7",
"111010":"7.7",
"211000":"7.7",
"002021":"7.6",
"101011":"7.6",
"101020":"7.6",
"110101":"7.6",
"210001":"7.6",
"100201":"7.5",
"110110":"7.5",
"111100":"7.5",
"201001":"7.5",
"201010":"7.5",
"100210":"7.4",
"101110":"7.4",
"110011":"7.4",
"112001":"7.4",
"200101":"7.4",
"200110":"7.4",
"210010":"7.4",
"010220":"7.3",
"011021":"7.3",
"100111":"7.3",
"201100":"7.3",
"102011":"7.2",
"202001":"7.2",
"210100":"7.2",
"011111":"7.1",
"012101":"7.1",
"101200":"7.1",
"200011":"7.1",
"002111":"7",
"010121":"7",
"010211":"7",
"011120":"7",
"011201":"7",
"011210":"7",
"110021":"7",
"200200":"7",
"002201":"6.9",
"001220":"6.8",
"110210":"6.8",
"001211":"6.7",
"101021":"6.7",
"000221":"6.6",
"001121":"6.7",
"110201":"6.6",
"111011":"6.6",
"210020":"6.6",
"102101":"6.7",
"100220":"6.4",
"201020":"6.3",
"100211":"6.2",
"211100":"6.1",
"111200":"6",
"110111":"5.9",
"101210":"5.8",
"111101":"5.9",
"200120":"6",
"101201":"5.9",
"201101":"5.7",
"211001":"5.8",
"012021":"6",
"111020":"5.9",
"211010":"5.9",
"101120":"6.4",
"210011":"5.8",
"200021":"5.3",
"210101":"5.8",
"010221":"5.2",
"011211":"5.4",
"101111":"6.2",
"111110":"6.5",
"201011":"5.7",
"012111":"6.3",
"200210":"5.6",
"100121":"6.2",
"110120":"5.9",
"001221":"4.9",
"210200":"5.4",
"201110":"6.6",
"102021":"5.4",
"210110":"5.6",
"200201":"5.6",
"002121":"6.2",
"112011":"5.6",
"200111":"5.6",
"011220":"6.4",
"201200":"6.4",
"002211":"5.9",
"110220":"5",
"211020":"4.8",
"011121":"6.7",
"012201":"6.6",
"212001":"3.9",
"110211":"4.8",
"111021":"5.2",
"202101":"5.5",
"100221":"4.4",
"102111":"5.4",
"112021":"3.7",
"112101":"5.9",
"111120":"4.7",
"111201":"5.2",
"200220":"4",
"102201":"5.1",
"111210":"5",
"211011":"4",
"202011":"5.4",
"101121":"4.9",
"101220":"4.8",
"111111":"5.6",
"210021":"3.5",
"101211":"4.5",
"200211":"3.8",
"210201":"3.4",
"110121":"5.2",
"201120":"5.4",
"201201":"3.9",
"210120":"4.8",
"210210":"3.6",
"012121":"4.5",
"012211":"4.8",
"201021":"3.5",
"210111":"4",
"211200":"4.3",
"211110":"4.3",
"200121":"3.5",
"201210":"4.6",
"211101":"4.4",
"011221":"3.6",
"102121":"3.6",
"212101":"2.7",
"002221":"4.1",
"212011":"2.6",
"110221":"2.5",
"201111":"3.9",
"202201":"2.4",
"111211":"3.4",
"112111":"4.1",
"112201":"2.2",
"101221":"2.7",
"111220":"3.2",
"200221":"2",
"202021":"2",
"210211":"2",
"111121":"3.8",
"202111":"3.7",
"211120":"2.3",
"102211":"3.3",
"201220":"1.8",
"210220":"1.7",
"211021":"1.7",
"012221":"1.7",
"201121":"1.6",
"201211":"2.1",
"210121":"1.7",
"211201":"1.6",
"211210":"2.5",
"211111":"2.6",
"212021":"1.4",
"111221":"1.3",
"112121":"1.9",
"102221":"1.2",
"112211":"1.2",
"212111":"1.2",
"202121":"1.1",
"212201":"1.1",
"202211":"1",
"210221":"0.9",
"211121":"0.9",
"211220":"0.9",
"201221":"0.8",
"211211":"0.7",
"112221":"0.6",
"212121":"0.5",
"202221":"0.4",
"212211":"0.3",
"211221":"0.2",
"212221":"0.1"
}

cvssLookup_adjusted = {
"000000":"10",
"000001":"10",
"000100":"10",
"000101":"10",
"010000":"9.9",
"000010":"9.8",
"001000":"9.8",
"100000":"9.8",
"010001":"9.7",
"011000":"9.7",
"001010":"9.6",
"010010":"9.6",
"010100":"9.6",
"000011":"9.5",
"000020":"9.5",
"001001":"9.5",
"100001":"9.5",
"110000":"9.5",
"000110":"9.4",
"100010":"9.4",
"100100":"9.4",
"101000":"9.4",
"000200":"9.3",
"001100":"9.3",
"002001":"9.3",
"010020":"9.3",
"011001":"9.3",
"200000":"9.3",
"000021":"9.2",
"000201":"9.2",
"010011":"9.2",
"010200":"9.2",
"011010":"9.2",
"011100":"9.2",
"000120":"9.1",
"001011":"9.1",
"010101":"9.1",
"000210":"9",
"001020":"9",
"001101":"9",
"010110":"9",
"100020":"9",
"110001":"9",
"110100":"9",
"001110":"8.9",
"001200":"8.9",
"012001":"8.9",
"100101":"8.9",
"200001":"8.9",
"101001":"8.8",
"101010":"8.8",
"111000":"8.8",
"000111":"8.7",
"100200":"8.7",
"110010":"8.7",
"210000":"8.7",
"011020":"8.6",
"200010":"8.6",
"200100":"8.6",
"001021":"8.5",
"010021":"8.5",
"011011":"8.5",
"011200":"8.5",
"100011":"8.5",
"100110":"8.5",
"102001":"8.5",
"201000":"8.5",
"002011":"8.4",
"010120":"8.4",
"101100":"8.4",
"001120":"8.3",
"002101":"8.3",
"010111":"8.3",
"010201":"8.2",
"010210":"8.2",
"000121":"8.1",
"000220":"8.1",
"001111":"8.1",
"011101":"8.1",
"001201":"8",
"011110":"8",
"100021":"8",
"000211":"7.9",
"001210":"7.9",
"012011":"7.8",
"200020":"7.8",
"100120":"7.7",
"101101":"7.7",
"110020":"7.7",
"110200":"7.7",
"111001":"7.7",
"111010":"7.7",
"211000":"7.7",
"002021":"7.6",
"101011":"7.6",
"101020":"7.6",
"110101":"7.6",
"210001":"7.6",
"100201":"7.5",
"110110":"7.5",
"111100":"7.5",
"201001":"7.5",
"201010":"7.5",
"100210":"7.4",
"101110":"7.4",
"110011":"7.4",
"112001":"7.4",
"200101":"7.4",
"200110":"7.4",
"210010":"7.4",
"010220":"7.3",
"011021":"7.3",
"100111":"7.3",
"201100":"7.3",
"102011":"7.2",
"202001":"7.2",
"210100":"7.2",
"011111":"7.1",
"012101":"7.1",
"101200":"7.1",
"200011":"7.1",
"002111":"7",
"010121":"7",
"010211":"7",
"011120":"7",
"011201":"7",
"011210":"7",
"110021":"7",
"200200":"7",
"002201":"6.9",
"001220":"6.8",
"110210":"6.8",
"001211":"6.7",
"101021":"6.7",
"000221":"6.6",
"001121":"6.7",
"110201":"6.6",
"111011":"6.6",
"210020":"6.6",
"102101":"6.7",
"100220":"6.4",
"201020":"6.3",
"100211":"6.2",
"211100":"6.1",
"111200":"6",
"110111":"5.9",
"101210":"5.8",
"111101":"5.9",
"200120":"6",
"101201":"5.9",
"201101":"5.7",
"211001":"5.8",
"012021":"5.5",
"111020":"5.9",
"211010":"5.6",
"101120":"6.4",
"210011":"5.3",
"200021":"5.2",
"210101":"5.8",
"010221":"5.2",
"011211":"5.4",
"101111":"6.2",
"111110":"6.5",
"201011":"5.3",
"012111":"6.3",
"200210":"5.6",
"100121":"6.2",
"110120":"5.9",
"001221":"4.8",
"210200":"5.4",
"201110":"6.6",
"102021":"4.9",
"210110":"5.6",
"200201":"5.6",
"002121":"6.2",
"112011":"4.8",
"200111":"5.3",
"011220":"6.4",
"201200":"6.4",
"002211":"5.9",
"110220":"4.1",
"211020":"4.8",
"011121":"6.7",
"012201":"6.6",
"212001":"3.9",
"110211":"4.1",
"111021":"5.2",
"202101":"5.5",
"100221":"3.7",
"102111":"5.4",
"112021":"3.7",
"112101":"5.9",
"111120":"3.6",
"111201":"5.2",
"200220":"4",
"102201":"5.1",
"111210":"5",
"211011":"3.5",
"202011":"3.4",
"101121":"4.9",
"101220":"4.8",
"111111":"5.6",
"210021":"3.3",
"101211":"4.5",
"200211":"3.2",
"210201":"3.4",
"110121":"5.2",
"201120":"5.4",
"201201":"3.9",
"210120":"4.8",
"210210":"3.1",
"012121":"3.7",
"012211":"3.5",
"201021":"3.4",
"210111":"3.5",
"211200":"4.3",
"211110":"3.6",
"200121":"3.4",
"201210":"3.3",
"211101":"4.4",
"011221":"3.3",
"102121":"2.8",
"212101":"2.7",
"002221":"3",
"212011":"2.6",
"110221":"2.5",
"201111":"3.4",
"202201":"2.4",
"111211":"2.3",
"112111":"2.6",
"112201":"2.2",
"101221":"2.1",
"111220":"2.3",
"200221":"2",
"202021":"2",
"210211":"2",
"111121":"2",
"202111":"1.9",
"211120":"2.3",
"102211":"1.9",
"201220":"1.8",
"210220":"1.7",
"211021":"1.7",
"012221":"1.6",
"201121":"1.6",
"201211":"1.6",
"210121":"1.6",
"211201":"1.6",
"211210":"1.5",
"211111":"1.7",
"212021":"1.4",
"111221":"1.3",
"112121":"1.9",
"102221":"1.2",
"112211":"1.2",
"212111":"1.2",
"202121":"1.1",
"212201":"1.1",
"202211":"1",
"210221":"0.9",
"211121":"0.9",
"211220":"0.9",
"201221":"0.8",
"211211":"0.7",
"112221":"0.6",
"212121":"0.5",
"202221":"0.4",
"212211":"0.3",
"211221":"0.2",
"212221":"0.1"
}

cvssLookup_cluster_mean = {
    "212221": 0.1,
    "211221": 0.9,
    "212211": 1.1,
    "202221": 1.2,
    "212121": 1.3,
    "112221": 1.6,
    "211211": 1.9,
    "201221": 2.1,
    "211121": 2.2,
    "211220": 2.2,
    "210221": 2.2,
    "202211": 2.3,
    "212201": 2.4,
    "202121": 2.4,
    "212111": 2.5,
    "102221": 2.5,
    "112211": 2.5,
    "111221": 2.7,
    "112121": 2.7,
    "212021": 2.9,
    "211111": 2.9,
    "211210": 3,
    "201121": 3,
    "211201": 3,
    "201211": 3,
    "210121": 3,
    "012221": 3,
    "102211": 3.1,
    "211021": 3.1,
    "210220": 3.1,
    "201220": 3.1,
    "211120": 3.2,
    "111121": 3.2,
    "202111": 3.2,
    "202021": 3.2,
    "210211": 3.2,
    "200221": 3.2,
    "111220": 3.3,
    "101221": 3.3,
    "112201": 3.4,
    "112111": 3.5,
    "111211": 3.5,
    "202201": 3.6,
    "110221": 3.6,
    "201111": 3.6,
    "212011": 3.7,
    "002221": 3.7,
    "212101": 3.8,
    "011221": 3.8,
    "102121": 3.8,
    "211101": 3.8,
    "201210": 3.8,
    "200121": 3.8,
    "211110": 3.9,
    "211200": 3.9,
    "210111": 3.9,
    "201021": 3.9,
    "012211": 3.9,
    "012121": 3.9,
    "210120": 4,
    "201201": 4,
    "201120": 4,
    "210210": 4,
    "110121": 4,
    "200211": 4.1,
    "101211": 4.1,
    "210201": 4.1,
    "210021": 4.2,
    "101220": 4.2,
    "101121": 4.2,
    "111111": 4.2,
    "202011": 4.2,
    "111210": 4.2,
    "102201": 4.2,
    "211011": 4.2,
    "111120": 4.3,
    "200220": 4.3,
    "111201": 4.3,
    "100221": 4.3,
    "102111": 4.3,
    "112101": 4.3,
    "112021": 4.3,
    "110211": 4.4,
    "202101": 4.4,
    "111021": 4.4,
    "212001": 4.5,
    "012201": 4.5,
    "011121": 4.6,
    "211020": 4.6,
    "110220": 4.6,
    "002211": 4.6,
    "201200": 4.7,
    "011220": 4.7,
    "002121": 4.8,
    "200111": 4.8,
    "112011": 4.8,
    "200201": 4.8,
    "102021": 4.8,
    "210110": 4.8,
    "201110": 4.8,
    "001221": 4.8,
    "210200": 4.8,
    "110120": 4.8,
    "100121": 4.8,
    "012111": 4.9,
    "200210": 4.9,
    "011211": 4.9,
    "111110": 4.9,
    "010221": 4.9,
    "201011": 4.9,
    "101111": 4.9,
    "210101": 5,
    "200021": 5,
    "101120": 5,
    "210011": 5,
    "111020": 5,
    "211010": 5,
    "012021": 5,
    "211001": 5,
    "201101": 5.1,
    "101201": 5.1,
    "111101": 5.1,
    "200120": 5.1,
    "101210": 5.1,
    "110111": 5.1,
    "111200": 5.1,
    "211100": 5.1,
    "100211": 5.1,
    "201020": 5.2,
    "100220": 5.2,
    "102101": 5.3,
    "210020": 5.3,
    "110201": 5.3,
    "000221": 5.3,
    "001121": 5.3,
    "111011": 5.3,
    "101021": 5.4,
    "001211": 5.4,
    "110210": 5.4,
    "001220": 5.4,
    "002201": 5.4,
    "011210": 5.4,
    "200200": 5.4,
    "011120": 5.5,
    "011201": 5.5,
    "110021": 5.5,
    "002111": 5.5,
    "010121": 5.5,
    "010211": 5.5,
    "012101": 5.6,
    "011111": 5.6,
    "200011": 5.6,
    "101200": 5.6,
    "202001": 5.7,
    "210100": 5.7,
    "102011": 5.7,
    "201100": 5.7,
    "100111": 5.7,
    "011021": 5.7,
    "010220": 5.7,
    "100210": 5.8,
    "200101": 5.8,
    "200110": 5.8,
    "112001": 5.8,
    "101110": 5.8,
    "110011": 5.8,
    "210010": 5.8,
    "100201": 5.9,
    "201010": 5.9,
    "111100": 5.9,
    "201001": 5.9,
    "110110": 5.9,
    "002021": 5.9,
    "101020": 5.9,
    "110101": 6,
    "101011": 6,
    "210001": 6,
    "211000": 6,
    "100120": 6,
    "111001": 6,
    "110020": 6,
    "101101": 6,
    "110200": 6,
    "111010": 6,
    "200020": 6.1,
    "012011": 6.1,
    "000211": 6.1,
    "001210": 6.1,
    "011110": 6.2,
    "001201": 6.2,
    "100021": 6.2,
    "000220": 6.3,
    "000121": 6.3,
    "001111": 6.3,
    "011101": 6.3,
    "010201": 6.3,
    "010210": 6.3,
    "002101": 6.3,
    "001120": 6.3,
    "010111": 6.4,
    "010120": 6.5,
    "002011": 6.5,
    "101100": 6.5,
    "011200": 6.5,
    "010021": 6.5,
    "001021": 6.5,
    "201000": 6.5,
    "100110": 6.5,
    "011011": 6.5,
    "102001": 6.6,
    "100011": 6.6,
    "200010": 6.6,
    "200100": 6.6,
    "011020": 6.6,
    "000111": 6.7,
    "110010": 6.7,
    "210000": 6.7,
    "100200": 6.7,
    "101001": 6.8,
    "101010": 6.8,
    "111000": 6.8,
    "200001": 6.8,
    "001200": 6.8,
    "012001": 6.8,
    "001110": 6.8,
    "100101": 6.8,
    "110001": 6.8,
    "010110": 6.9,
    "000210": 6.9,
    "110100": 6.9,
    "001020": 6.9,
    "100020": 7,
    "001101": 7,
    "000120": 7.1,
    "001011": 7.1,
    "010101": 7.1,
    "000201": 7.1,
    "011100": 7.1,
    "010011": 7.1,
    "010200": 7.2,
    "011010": 7.2,
    "000021": 7.2,
    "002001": 7.3,
    "010020": 7.3,
    "011001": 7.4,
    "200000": 7.4,
    "001100": 7.4,
    "000200": 7.4,
    "100010": 7.5,
    "100100": 7.6,
    "000110": 7.6,
    "101000": 7.6,
    "000011": 7.8,
    "110000": 7.8,
    "100001": 7.8,
    "000020": 7.8,
    "001001": 7.8,
    "010100": 7.9,
    "001010": 7.9,
    "010010": 8,
    "011000": 8,
    "010001": 8.2,
    "100000": 8.6,
    "001000": 8.6,
    "000010": 8.6,
    "010000": 8.9,
    "000100": 9.8,
    "000001": 9.9,
    "000101": 9.9,
    "000000": 10
  }

  cvssLookup_linear = {
    "212221": 0.1,
    "211221": 1,
    "212211": 1.1,
    "202221": 1.3,
    "212121": 1.3,
    "112221": 1.7,
    "211211": 1.9,
    "201221": 2.2,
    "211121": 2.2,
    "211220": 2.2,
    "210221": 2.3,
    "202211": 2.4,
    "212201": 2.4,
    "202121": 2.5,
    "212111": 2.5,
    "102221": 2.5,
    "112211": 2.5,
    "111221": 2.7,
    "112121": 2.8,
    "212021": 2.9,
    "211111": 2.9,
    "211210": 3,
    "201121": 3.1,
    "211201": 3.1,
    "201211": 3.1,
    "210121": 3.1,
    "012221": 3.1,
    "102211": 3.2,
    "211021": 3.2,
    "210220": 3.2,
    "201220": 3.2,
    "211120": 3.2,
    "111121": 3.3,
    "202111": 3.3,
    "202021": 3.3,
    "210211": 3.3,
    "200221": 3.3,
    "111220": 3.4,
    "101221": 3.4,
    "112201": 3.4,
    "112111": 3.6,
    "111211": 3.6,
    "202201": 3.6,
    "110221": 3.7,
    "201111": 3.7,
    "212011": 3.7,
    "002221": 3.8,
    "212101": 3.8,
    "011221": 3.8,
    "102121": 3.8,
    "211101": 3.9,
    "201210": 3.9,
    "200121": 3.9,
    "211110": 3.9,
    "211200": 4,
    "210111": 4,
    "201021": 4,
    "012211": 4,
    "012121": 4,
    "210120": 4,
    "201201": 4,
    "201120": 4.1,
    "210210": 4.1,
    "110121": 4.1,
    "200211": 4.1,
    "101211": 4.1,
    "210201": 4.2,
    "210021": 4.2,
    "101220": 4.2,
    "101121": 4.2,
    "111111": 4.2,
    "202011": 4.2,
    "111210": 4.3,
    "102201": 4.3,
    "211011": 4.3,
    "111120": 4.3,
    "200220": 4.3,
    "111201": 4.3,
    "100221": 4.4,
    "102111": 4.4,
    "112101": 4.4,
    "112021": 4.4,
    "110211": 4.4,
    "202101": 4.5,
    "111021": 4.5,
    "212001": 4.5,
    "012201": 4.5,
    "011121": 4.6,
    "211020": 4.6,
    "110220": 4.7,
    "002211": 4.7,
    "201200": 4.7,
    "011220": 4.8,
    "002121": 4.8,
    "200111": 4.8,
    "112011": 4.8,
    "200201": 4.8,
    "102021": 4.8,
    "210110": 4.8,
    "201110": 4.9,
    "001221": 4.9,
    "210200": 4.9,
    "110120": 4.9,
    "100121": 4.9,
    "012111": 4.9,
    "200210": 4.9,
    "011211": 4.9,
    "111110": 5,
    "010221": 5,
    "201011": 5,
    "101111": 5,
    "210101": 5,
    "200021": 5,
    "101120": 5,
    "210011": 5,
    "111020": 5,
    "211010": 5,
    "012021": 5.1,
    "211001": 5.1,
    "201101": 5.1,
    "101201": 5.1,
    "111101": 5.1,
    "200120": 5.1,
    "101210": 5.1,
    "110111": 5.1,
    "111200": 5.2,
    "211100": 5.2,
    "100211": 5.2,
    "201020": 5.3,
    "100220": 5.3,
    "102101": 5.4,
    "210020": 5.4,
    "110201": 5.4,
    "000221": 5.4,
    "001121": 5.4,
    "111011": 5.4,
    "101021": 5.4,
    "001211": 5.4,
    "110210": 5.4,
    "001220": 5.4,
    "002201": 5.5,
    "011210": 5.5,
    "200200": 5.5,
    "011120": 5.5,
    "011201": 5.5,
    "110021": 5.5,
    "002111": 5.5,
    "010121": 5.5,
    "010211": 5.5,
    "012101": 5.6,
    "011111": 5.6,
    "200011": 5.7,
    "101200": 5.7,
    "202001": 5.7,
    "210100": 5.7,
    "102011": 5.7,
    "201100": 5.7,
    "100111": 5.8,
    "011021": 5.8,
    "010220": 5.8,
    "100210": 5.8,
    "200101": 5.8,
    "200110": 5.8,
    "112001": 5.9,
    "101110": 5.9,
    "110011": 5.9,
    "210010": 5.9,
    "100201": 5.9,
    "201010": 5.9,
    "111100": 5.9,
    "201001": 5.9,
    "110110": 5.9,
    "002021": 6,
    "101020": 6,
    "110101": 6,
    "101011": 6,
    "210001": 6,
    "211000": 6,
    "100120": 6.1,
    "111001": 6.1,
    "110020": 6.1,
    "101101": 6.1,
    "110200": 6.1,
    "111010": 6.1,
    "200020": 6.1,
    "012011": 6.2,
    "000211": 6.2,
    "001210": 6.2,
    "011110": 6.2,
    "001201": 6.2,
    "100021": 6.3,
    "000220": 6.3,
    "000121": 6.3,
    "001111": 6.3,
    "011101": 6.3,
    "010201": 6.4,
    "010210": 6.4,
    "002101": 6.4,
    "001120": 6.4,
    "010111": 6.4,
    "010120": 6.5,
    "002011": 6.5,
    "101100": 6.5,
    "011200": 6.6,
    "010021": 6.6,
    "001021": 6.6,
    "201000": 6.6,
    "100110": 6.6,
    "011011": 6.6,
    "102001": 6.6,
    "100011": 6.6,
    "200010": 6.7,
    "200100": 6.7,
    "011020": 6.7,
    "000111": 6.8,
    "110010": 6.8,
    "210000": 6.8,
    "100200": 6.8,
    "101001": 6.8,
    "101010": 6.8,
    "111000": 6.8,
    "200001": 6.9,
    "001200": 6.9,
    "012001": 6.9,
    "001110": 6.9,
    "100101": 6.9,
    "110001": 6.9,
    "010110": 6.9,
    "000210": 7,
    "110100": 7,
    "001020": 7,
    "100020": 7,
    "001101": 7,
    "000120": 7.1,
    "001011": 7.1,
    "010101": 7.1,
    "000201": 7.1,
    "011100": 7.1,
    "010011": 7.2,
    "010200": 7.2,
    "011010": 7.2,
    "000021": 7.3,
    "002001": 7.3,
    "010020": 7.3,
    "011001": 7.5,
    "200000": 7.5,
    "001100": 7.5,
    "000200": 7.5,
    "100010": 7.6,
    "100100": 7.6,
    "000110": 7.7,
    "101000": 7.7,
    "000011": 7.8,
    "110000": 7.8,
    "100001": 7.9,
    "000020": 7.9,
    "001001": 7.9,
    "010100": 8,
    "001010": 8,
    "010010": 8,
    "011000": 8.1,
    "010001": 8.2,
    "100000": 8.6,
    "001000": 8.7,
    "000010": 8.7,
    "010000": 9,
    "000100": 9.8,
    "000001": 10,
    "000101": 10,
    "000000": 10
  }

  cvssLookup_rank_bin = {
    "212221": 0.1,
    "211221": 0.1,
    "212211": 0.2,
    "202221": 0.2,
    "212121": 0.2,
    "112221": 0.3,
    "211211": 0.3,
    "201221": 0.3,
    "211121": 0.4,
    "211220": 0.4,
    "210221": 0.5,
    "202211": 0.5,
    "212201": 0.5,
    "202121": 0.6,
    "212111": 0.6,
    "102221": 0.6,
    "112211": 0.7,
    "111221": 0.7,
    "112121": 0.8,
    "212021": 0.8,
    "211111": 0.8,
    "211210": 0.9,
    "201121": 0.9,
    "211201": 0.9,
    "201211": 1,
    "210121": 1,
    "012221": 1,
    "102211": 1.1,
    "211021": 1.1,
    "210220": 1.2,
    "201220": 1.2,
    "211120": 1.2,
    "111121": 1.3,
    "202111": 1.3,
    "202021": 1.3,
    "210211": 1.4,
    "200221": 1.4,
    "111220": 1.5,
    "101221": 1.5,
    "112201": 1.5,
    "112111": 1.6,
    "111211": 1.6,
    "202201": 1.6,
    "110221": 1.7,
    "201111": 1.7,
    "212011": 1.8,
    "002221": 1.8,
    "212101": 1.8,
    "011221": 1.9,
    "102121": 1.9,
    "211101": 1.9,
    "201210": 2,
    "200121": 2,
    "211110": 2,
    "211200": 2.1,
    "210111": 2.1,
    "201021": 2.2,
    "012211": 2.2,
    "012121": 2.2,
    "210120": 2.3,
    "201201": 2.3,
    "201120": 2.3,
    "210210": 2.4,
    "110121": 2.4,
    "200211": 2.5,
    "101211": 2.5,
    "210201": 2.5,
    "210021": 2.6,
    "101220": 2.6,
    "101121": 2.6,
    "111111": 2.7,
    "202011": 2.7,
    "111210": 2.8,
    "102201": 2.8,
    "211011": 2.8,
    "111120": 2.9,
    "200220": 2.9,
    "111201": 2.9,
    "100221": 3,
    "102111": 3,
    "112101": 3,
    "112021": 3.1,
    "110211": 3.1,
    "202101": 3.2,
    "111021": 3.2,
    "212001": 3.2,
    "012201": 3.3,
    "011121": 3.3,
    "211020": 3.3,
    "110220": 3.4,
    "002211": 3.4,
    "201200": 3.5,
    "011220": 3.5,
    "002121": 3.5,
    "200111": 3.6,
    "112011": 3.6,
    "200201": 3.6,
    "102021": 3.7,
    "210110": 3.7,
    "201110": 3.8,
    "001221": 3.8,
    "210200": 3.8,
    "110120": 3.9,
    "100121": 3.9,
    "012111": 3.9,
    "200210": 4,
    "011211": 4,
    "111110": 4,
    "010221": 4.1,
    "201011": 4.1,
    "101111": 4.2,
    "210101": 4.2,
    "200021": 4.2,
    "101120": 4.3,
    "210011": 4.3,
    "111020": 4.3,
    "211010": 4.4,
    "012021": 4.4,
    "211001": 4.5,
    "201101": 4.5,
    "101201": 4.5,
    "111101": 4.6,
    "200120": 4.6,
    "101210": 4.6,
    "110111": 4.7,
    "111200": 4.7,
    "211100": 4.8,
    "100211": 4.8,
    "201020": 4.8,
    "100220": 4.9,
    "102101": 4.9,
    "210020": 4.9,
    "110201": 5,
    "000221": 5,
    "001121": 5,
    "111011": 5.1,
    "101021": 5.1,
    "001211": 5.2,
    "110210": 5.2,
    "001220": 5.2,
    "002201": 5.3,
    "011210": 5.3,
    "200200": 5.3,
    "011120": 5.4,
    "011201": 5.4,
    "110021": 5.5,
    "002111": 5.5,
    "010121": 5.5,
    "010211": 5.6,
    "012101": 5.6,
    "011111": 5.6,
    "200011": 5.7,
    "101200": 5.7,
    "202001": 5.8,
    "210100": 5.8,
    "102011": 5.8,
    "201100": 5.9,
    "100111": 5.9,
    "011021": 5.9,
    "010220": 6,
    "100210": 6,
    "200101": 6,
    "200110": 6.1,
    "112001": 6.1,
    "101110": 6.2,
    "110011": 6.2,
    "210010": 6.2,
    "100201": 6.3,
    "201010": 6.3,
    "111100": 6.3,
    "201001": 6.4,
    "110110": 6.4,
    "002021": 6.5,
    "101020": 6.5,
    "110101": 6.5,
    "101011": 6.6,
    "210001": 6.6,
    "211000": 6.6,
    "100120": 6.7,
    "111001": 6.7,
    "110020": 6.8,
    "101101": 6.8,
    "110200": 6.8,
    "111010": 6.9,
    "200020": 6.9,
    "012011": 6.9,
    "000211": 7,
    "001210": 7,
    "011110": 7,
    "001201": 7.1,
    "100021": 7.1,
    "000220": 7.2,
    "000121": 7.2,
    "001111": 7.2,
    "011101": 7.3,
    "010201": 7.3,
    "010210": 7.3,
    "002101": 7.4,
    "001120": 7.4,
    "010111": 7.5,
    "010120": 7.5,
    "002011": 7.5,
    "101100": 7.6,
    "011200": 7.6,
    "010021": 7.6,
    "001021": 7.7,
    "201000": 7.7,
    "100110": 7.8,
    "011011": 7.8,
    "102001": 7.8,
    "100011": 7.9,
    "200010": 7.9,
    "200100": 7.9,
    "011020": 8,
    "000111": 8,
    "110010": 8,
    "210000": 8.1,
    "100200": 8.1,
    "101001": 8.2,
    "101010": 8.2,
    "111000": 8.2,
    "200001": 8.3,
    "001200": 8.3,
    "012001": 8.3,
    "001110": 8.4,
    "100101": 8.4,
    "110001": 8.5,
    "010110": 8.5,
    "000210": 8.5,
    "110100": 8.6,
    "001020": 8.6,
    "100020": 8.6,
    "001101": 8.7,
    "000120": 8.7,
    "001011": 8.8,
    "010101": 8.8,
    "000201": 8.8,
    "011100": 8.9,
    "010011": 8.9,
    "010200": 8.9,
    "011010": 9,
    "000021": 9,
    "002001": 9,
    "010020": 9.1,
    "011001": 9.1,
    "200000": 9.2,
    "001100": 9.2,
    "000200": 9.2,
    "100010": 9.3,
    "100100": 9.3,
    "000110": 9.3,
    "101000": 9.4,
    "000011": 9.4,
    "110000": 9.5,
    "100001": 9.5,
    "000020": 9.5,
    "001001": 9.6,
    "010100": 9.6,
    "001010": 9.6,
    "010010": 9.7,
    "011000": 9.7,
    "010001": 9.8,
    "100000": 9.8,
    "001000": 9.8,
    "000010": 9.9,
    "010000": 9.9,
    "000100": 9.9,
    "000001": 10,
    "000101": 10,
    "000000": 10
  }
  
