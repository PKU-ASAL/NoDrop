import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter
from math import ceil

x = {}
y = {}

labels = ['SecureProv', 'Sysdig', 'Sysdig-simplify', 'LTTng']

def update_scale_value(temp, position):
    result = temp//1e6
    return "{}M".format(int(result))

def parse_max(x, y):
	mx = 0
	for i, j in zip(x, y):
		mx = max(mx, i, j)
	return mx

def parse_min(x, y):
	mn = 1e9
	for i, j in zip(x, y):
		mn = min(mn, i, j)
	return mn

x['SecureProv'] = [2000030,8000090,20000210,40000410,60000610,80000810,100001010,120001210,140001410,160001610,180001810,200002010,400002010,450002010,500002010]
y['SecureProv'] = [2000030,8000090,20000210,40000410,60000610,80000810,100001010,120001210,140001410,160001610,180001810,200002010,400002010,450002010,500002010]

x['Sysdig'] = [2000030,8000090,20000210,40000410,60000610,80000810,100001010,120001210,140001410,160001610,180001810,200002010,400002010,450002010,500002010]
y['Sysdig'] = [2000030,7946015,9013790,10718494,10814330,8710943,9004386,8706786,8752668,10837080,8714622,9980336,9365730,9190539,17243789]

x['Sysdig-simplify'] = [2000030,8000090,20000210,40000410,60000610,80000810,100001010,120001210,140001410,160001610,180001810,200002010,400002010,450002010,500002010]
y['Sysdig-simplify'] = [2000030,7997397,10984725,12389693,9093997,9357136,9383216,10050384,9525492,9295535,9050433,10185235,17541791,18449550,19547031]

x['LTTng'] = [2000030,8000090,20000210,40000410,60000610,80000810,100001010,120001210,140001410,160001610,180001810,200002010,400002010,450002010,500002010]
# y['LTTng'] = [2000030,8000090,20000210,40000410,41513972,42540070,49675207,44205291,54333117,60040777,50512413,53492484,94284444,105782966,102288700]
y['LTTng'] = [2000030,8000090,20000210,40000410,46384708,46145654,49163761,48879264,49092422,54209117,47383481,57597620,85482847,94560555,108248057]

plt.figure()
mx, mn = 0, 1e9
for i, k in enumerate(labels):

	x[k] = x[k][:7]
	y[k] = y[k][:7]

	lw = 3 - 2 * i / len(labels)
	ls = ['-','--','-.',':'][i % 4]

	plt.plot(x[k], y[k], linestyle=ls, label=k, linewidth=lw)
	mx = max(mx, parse_max(x[k], y[k]))
	mn = min(mn, parse_min(x[k], y[k]))
mn = int(mn * 0.95)
mx = ceil(mx * 1.05)
plt.plot([mn, mx], [mn, mx], '--', color='gray', label='No drop')
plt.xlim(mn, mx)
plt.ylim(mn, mx)
plt.ylabel('#Received Events')
plt.xlabel('#Total Events')
plt.legend()
plt.gca().xaxis.set_major_formatter(FuncFormatter(update_scale_value))
plt.gca().yaxis.set_major_formatter(FuncFormatter(update_scale_value))
plt.savefig('tool-all.pdf', bbox_inches='tight', pad_inches=0)
plt.show()