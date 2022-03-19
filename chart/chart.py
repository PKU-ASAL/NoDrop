import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import numpy as np

# sysdig = [8, 16, 8, 32, 32, 0, 16, 40, 16, 24]
# secuprob = [48, 48, 48, 48, 48, 48, 48, 48, 48, 48]
# events = [3418718.433, 3422027.3, 3351963.667, 3346181.6, 3392800.2, 3362647.333, 3410349.167, 3433164.367, 3373604.333, 3407637.9]
# xlabel = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
# x = np.arange(10)

# width = 0.3

# fig = plt.figure()
# ax1 = fig.add_subplot(111)

# plt.bar(x - width / 2, sysdig, width=width, label='Sysdig')
# plt.bar(x + width / 2, secuprob, width=width, label='SecureProv')
# ax1.set_ylim((0, 65))
# ax1.set_ylabel('Number of captured syscalls')
# plt.xticks(x, xlabel)
# plt.legend(loc='upper left')

# for a, b in zip(x, sysdig):
#     plt.text(a - width / 2, b, b, ha='center', va= 'bottom', fontsize=9)
# for a, b in zip(x, secuprob)
#     plt.text(a + width / 2, b, b, ha='center', va= 'bottom', fontsize=9)

# ax2 = ax1.twinx()
# ax2.plot(x, events, 'g-', label='Events/s')
# ax2.set_ylim((min(events) / 3, max(events) * 1.15))
# plt.legend()
# plt.savefig("attack.pdf", bbox_inches='tight', pad_inches=0)
# plt.show()

def solve_out_log(name, N):
    count_d = {}
    ret = []
    with open(name, "r") as f:
        for line in f.readlines():
            try:
                data = line.split()[-1]
                ts, total, drop, cpu = list(map(int, data.split(',')))
                count_d[ts] = count_d.get(ts, 0) + total
            except Exception:
                continue
    for k in sorted(count_d.keys()):
        if count_d[k] == 0:
            continue
        ret.append(count_d[k])
    if len(ret) > 1000 * N // 50:
        ret = ret[:1000 * N // 50]
    return ret

def translate(x, base):
    n = max(base // 50, 1)
    ret = []
    i = 0
    while i < len(x):
        tmp = 0
        for j in range(n):
            tmp += x[i + j]
        ret.append(tmp)
        i += n

    tmp = 0
    for i in range(len(x) % n):
        tmp += x[len(x) - len(x) % n + i]
    if tmp > 0:
        ret.append(tmp) 
    return ret;



# count = [122458,194489,197617,205900,217075,182526,210326,202759,196682,212513,181311,207596,202528,179344,205588,182006,189265,204672,202786,208522,197021,202303,207355,197690,206479,203717,193162,205010,201876,209217,202334,203318,202164,202248,210428,208958,201120,207673,207008,208181,207613,198897,207730,189568,212498,205866,207788,204419,206194,200132,199751,205985,202969,201649,204476,212524,204844,208745,203814,205390,204328,202927,208104,196362,208909,197767,200993,211120,202840,212254,202407,208428,205056,199039,199186,203496,202334,203141,213349,202864,208512,200594,205788,209952,203633,206010,199973,210018,205529,212704,201950,204582,205107,199527,212496,202687,203458,209043,210389,210367,204872,203531,199220,213795,211885,205474,211235,210633,209994,207478,202740,206240,197875,207164,207512,209026,213785,201367,206513,206370,212262,207506,198595,200808,204783,202029,204060,198786,201549,207105,209758,207330,202268,201788,207315,212565,209211,209763,211612,199731,197840,198387,202172,204561,210912,208054,207718,210982,205390,207521,201936,211345,189894,213259,211943,209360,208949,211512,205228,208551,199644,202525,194617,203502,206203,204179,205895,209975,208546,211326,199209,208289,200356,207540,210291,206394,212026,208618,208228,208537,192306,205440,195232,197185,206359,206627,208716,202364,209226,205777,206794,211448,215928,218878,225245,218981,219371,220306,218300,224482]
# count = [132737,210575,194563,189884,208437,185179,191322,212034,183240,205263,192633,192492,204869,192591,195322,202095,187148,204537,193625,193841,207188,184896,205240,196252,189937,207147,189450,202261,197213,186698,204319,193558,195585,204678,187542,203259,199012,190068,204216,195738,193189,198657,193616,201304,193753,197324,201328,190294,202782,199614,194326,202305,194177,198588,200119,195866,204655,191599,190909,204446,193024,199396,199100,195577,198396,197345,191398,200904,197247,202821,190987,199641,203656,193371,198740,199019,187340,196384,193636,195759,200531,195169,199376,194701,194349,195803,192024,199816,198481,196065,199264,198584,193380,202179,194975,196668,199543,195211,196041,199022,198877,198422,193971,197963,197527,194819,198395,193425,198438,198003,201753,193647,196821,194834,201214,195906,198771,200627,193388,198403,195093,196204,200995,193711,200245,196431,191189,197204,179041,197642,198623,196709,201026,195284,196431,198600,196318,198999,194498,190083,203761,193489,196830,190774,186296,200923,192788,201755,199331,188592,205523,191455,196063,205459,186868,204759,198086,195775,196335,191287,191740,192069,196131,202622,190639,200550,200454,192390,204009,196719,196115,201796,192972,201597,198575,189249,207830,194725,199058,190520,186207,199108,191900,202651,200343,194774,203308,201111,198102,202044,191083,201357,196178,195039,198735,200496,196273,196303,188812,197982]
# count = [40406,200466,205656,171453,203757,204702,193713,214537,188183,201314,212358,184840,214557,195252,201866,206952,192812,212206,203404,192792,206594,203096,202588,206935,200736,205193,201524,204031,200433,209339,196943,203784,203420,203367,201232,197190,211656,201664,201808,201318,201174,208162,205464,208223,202961,196636,209660,209032,196815,212050,199814,207115,208194,197397,208542,197298,201869,211912,191415,202293,193886,201063,207705,196468,211077,197358,204879,206694,186316,209787,201096,200611,213152,189508,210207,207358,195987,214657,191988,208523,199593,195168,206082,195864,208174,207537,192204,214242,194853,204885,209130,196549,211096,202548,198836,206031,190506,216944,200414,196641,208100,200997,208899,200795,201208,206233,189844,187931,184084,202357,212675,197986,211813,207077,201996,208972,205267,212753,196518,199446,214816,196642,213727,204989,198808,211774,203794,203681,205665,200110,207404,199182,205015,209514,200554,211725,205326,198601,203103,205969,206897,198170,199355,207189,210411,208092,206834,207731,200931,215390,202946,206527,204768,202876,209899,210387,207947,201885,200854,206555,197893,205352,211092,194744,216733,196756,213675,203418,204557,216937,188615,216584,210464,198882,218523,191581,218299,204875,185983,213990,192489,213210,206113,200124,215973,188906,220019,205285,200305,217443,196014,214126,207838,223360,220585,219673,223710,173620,115465,210785]
# 105-10s
# count = [119823,244826,251040,252455,251320,250747,252125,251478,252489,252814,251876,252532,252427,252143,251997,251410,251517,251275,252520,251830,251347,248570,241752,240793,240220,241231,240441,231455,231266,235229,235100,234668,234845,233004,234041,234548,234850,235797,234221,234104,234172,235013,233005,231387,235261,237074,235880,237077,235845,235826,235246,233788,236077,235558,236402,237875,230880,227146,236668,236424,234687,234718,237116,237409,230947,230581,233675,235801,235306,235420,235925,236332,236015,237055,236509,234628,237959,231429,232091,231290,231201,230645,233455,232825,232468,224899,220327,221137,228307,230773,232147,231161,232437,234713,234190,233950,231491,232970,232179,233978,233374,232634,234777,232386,232424,233382,232123,232882,227249,232074,230868,233626,237949,236946,231188,233092,229722,232063,233831,234128,232817,233188,234535,233788,236287,234582,233595,232597,232374,231667,226443,229422,231916,230270,235129,235823,235973,235848,235686,237843,234959,234974,236293,231086,232918,232187,231531,231198,233112,233469,234941,234749,227941,229865,232419,232115,230511,234893,235317,233123,236862,235689,235568,233778,235878,233873,232472,231288,235197,233124,232503,234366,229781,231242,227667,225190,231563,222927,232004,236181,235015,234685,234620,235363,233964,235272,235981,233823,236377,235001,235118,235061,232961,235149,236116,236159,230883,230988,236105,232894]
# sysdig_count = solve_out_log("sysdig-chisel-out-105.log", 10)
# baseline_count = solve_out_log("baseline-out-105.log", 10)
# 105-30s
count = [21227,219235,247045,249881,250228,249487,249624,249739,249511,250302,250233,250004,250287,250360,250307,249853,249634,250137,249783,249793,247445,289184,245759,245453,246016,245803,244799,245605,238806,236708,241399,242379,242969,243001,242483,242725,242373,242587,242455,242333,241933,240707,241351,240353,240484,241130,241377,240859,241557,240666,241280,241082,240790,241357,240885,241139,240891,239339,235617,234050,237030,236900,240909,239393,242374,241890,241301,241623,241579,241652,242936,242702,242346,242395,241971,241208,241306,241544,242330,241680,242034,239203,240982,237531,238778,240958,241868,241574,237958,234660,236999,238180,238879,241591,241516,242482,241865,242040,241812,241373,241593,240563,240905,240093,238787,239287,241433,241304,241759,242219,242285,242727,242243,241797,242551,241172,241756,242215,238919,234477,238410,238294,238106,241961,234782,241724,239681,241143,241751,241659,241390,240946,242128,242714,242427,242253,241972,241725,242182,240721,241925,241718,239271,241269,239281,236094,238974,237743,237364,233719,238582,236885,240141,238469,241652,241406,239415,241510,242257,242187,242563,242049,239696,241826,241719,237387,238886,241273,239840,241959,241717,241580,241856,242515,241830,241435,241677,242426,239764,238121,236062,239639,235611,239963,237857,240026,236386,234474,236439,236980,239203,238655,239843,239857,239025,239052,239933,239614,239923,238794,239560,239260,238517,236943,239287,239294,237320,236040,235251,239548,230978,240384,238547,238249,239851,237749,240759,239951,242070,238440,242472,242218,241710,240284,242892,243078,242349,237658,240372,239495,242574,239648,240258,240761,238998,239052,240029,239812,238544,239203,234252,240408,240819,234324,239116,240047,237257,239806,236621,231659,234782,239939,240225,241012,242637,241380,240354,241237,241712,242872,242114,241531,240000,237077,240984,240259,241443,238964,239279,240830,227807,236734,238411,235448,236984,240779,237712,236671,239960,240606,240329,237976,237670,238687,240725,241446,242164,241706,239875,240606,241585,234996,238585,241642,239364,240083,240554,241212,238556,240952,238873,237972,239438,237896,236249,238793,240820,238291,235846,236527,240077,237054,236889,236190,240139,237757,238228,240635,240249,239889,239832,240426,240250,240758,238253,240136,238509,240911,239025,238789,240694,234985,235840,238928,239146,239954,237528,239742,239404,239419,238704,242527,239899,242623,239635,238730,242878,241156,242519,241547,238407,241187,241617,237220,241342,243490,243314,240111,239582,241866,242550,234864,239966,242460,238978,240648,239862,241617,241917,241244,238611,237901,240069,237420,236346,241031,238776,237722,238149,238628,239802,238582,240596,240385,239153,240246,241312,240723,240616,240296,241936,237024,237577,241515,237107,236539,240372,239305,240757,238018,237871,238457,237677,238676,239420,238995,240534,240938,236783,238434,240914,239586,238842,240657,238431,235922,239285,238766,241538,238494,238870,238432,237621,240287,242817,238965,241506,242258,240134,243182,244093,240759,243553,237079,243048,239341,238848,241216,243185,243973,235405,237922,240576,240494,238976,240202,240568,239432,240304,238794,240103,238776,239005,237483,240359,239435,233144,238525,238893,238301,241446,238603,236525,239390,236674,240876,239518,241368,240936,241578,240702,240095,237634,239969,238978,240710,241284,236402,237638,239421,239885,240564,238385,232708,238327,240449,237725,239929,241885,238534,240111,241326,241317,239789,240446,238229,242099,238218,239370,240762,240574,242663,242622,237399,235833,241307,241258,242269,238915,240933,240615,241813,242252,239646,239564,240237,242253,240333,237501,240431,238643,239602,239618,241441,239111,235973,234678,237170,241929,239945,238677,240380,240993,238809,241017,237993,239910,241603,238073,235951,238112,241811,241779,239472,239572,240620,238034,236048,241094,242280,241222,238239,239787,241696,242090,240012,239179,242157,240480,237170,238791,239534,241843,237227,241714,242453,240413,233051,239650,240228,240536,241486,239762,241129,239492,242822,242776,240389,242426,240957,237323,240808,234071,242974,241922,240403,238237,239381,235969,235096,240442,241093,240952,236305,240643,239767,239187,239373,238131,234291]
sysdig_count = solve_out_log("sysdig-105-30.log", 30)
baseline_count = solve_out_log("baseline-105-30.log", 30)

count = translate(count, 1000)
sysdig_count = translate(sysdig_count, 1000)
baseline_count = translate(baseline_count, 1000)
x = np.arange(30)

mean_count = np.mean(count)
sysdig_mean = np.mean(sysdig_count)
baseline_mean = np.mean(baseline_count)

print(abs(sysdig_mean - mean_count) / sysdig_mean)

def y_update_scale_value(temp, position):
    result = temp//1000
    return "{}k".format(int(result))

fig = plt.figure()
plt.plot(x, count, color='skyblue', label="SecueProv")
plt.plot(x, sysdig_count, color='bisque', label="Sysdig")
plt.plot(x, baseline_count, color='lightcoral', label="Baseline")
# plt.hlines(mean_count, x[0], x[-1], linestyle='--', colors='dodgerblue', linewidth=1.0)
# plt.hlines(sysdig_mean, x[0], x[-1], linestyle='--', colors='orange', linewidth=1.0)
# plt.hlines(baseline_mean, x[0], x[-1], linestyle='--', colors='red', linewidth=1.0)
plt.xlabel("Time")
plt.ylabel("Number of System Calls")
plt.ylim(0, max(max(count), max(sysdig_count), max(baseline_count)) * 1.1)
plt.gca().yaxis.set_major_formatter(FuncFormatter(y_update_scale_value))
plt.legend()
plt.savefig("stresstest.pdf", bbox_inches='tight', pad_inches=0)
plt.show()
