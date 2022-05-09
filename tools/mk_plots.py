import pandas as pd
import matplotlib.pyplot as plt

locality="0"

default="nf_tables_default-"+locality+"_2.csv"
per_cpu="nf_tables_per_cpu-"+locality+"_2.csv"
global_list="nf_tables_glob_lock-"+locality+"_0.csv"

df = pd.read_csv(default)
df1 = pd.read_csv(per_cpu)
#df2 = pd.read_csv(global_list)
print(df1)
#plt.plot(df['acl1_s'], df['acl1'], label='acl1 default')
#plt.plot(df['acl2_s'], df['acl2'], label='acl2 default')
#plt.plot(df['acl3_s'], df['acl3'], label='acl3 default')
#plt.plot(df['acl4_s'], df['acl4'], label='acl4 default')
#plt.plot(df['acl5_s'], df['acl5'], label='acl5 default')
#plt.plot(df['fw1_s'], df['fw1'], label='fw1 default')
plt.plot(df['fw2_s'], df['fw2'], label='fw2 default')
#plt.plot(df['fw3_s'], df['fw3'], label='fw3 default')
#plt.plot(df['fw4_s'], df['fw4'], label='fw4 default')
#plt.plot(df['fw5_s'], df['fw5'], label='fw5 default')
#plt.plot(df['ipc1_s'], df['ipc1'], label='ipc1 default')
#plt.plot(df['ipc2_s'], df['ipc2'], label='ipc2 default')

#plt.plot(df1['acl1_s'], df1['acl1'], label='acl1 per cpu')
#plt.plot(df1['acl2_s'], df1['acl2'], label='acl2 per cpu')
#plt.plot(df1['acl3_s'], df1['acl3'], label='acl3 per cpu')
#plt.plot(df1['acl4_s'], df1['acl4'], label='acl4 per cpu')
#plt.plot(df1['acl5_s'], df1['acl5'], label='acl5 per cpu')
#plt.plot(df1['fw1_s'], df1['fw1'], label='fw1 per cpu')
plt.plot(df1['fw2_s'], df1['fw2'], label='fw2 per cpu')
#plt.plot(df1['fw3_s'], df1['fw3'], label='fw3 per cpu')
#plt.plot(df1['fw4_s'], df1['fw4'], label='fw4 per cpu')
#plt.plot(df1['fw5_s'], df1['fw5'], label='fw5 per cpu')
#plt.plot(df1['ipc1_s'], df1['ipc1'], label='ipc1 per cpu')
#plt.plot(df1['ipc2_s'], df1['ipc2'], label='ipc2 per cpu')


#plt.plot(df2['acl1_s'], df2['acl1'], label='acl1 global list')
#plt.plot(df2['acl2_s'], df2['acl2'], label='acl2 global list')
#plt.plot(df2['acl3_s'], df2['acl3'], label='acl3 global list')
#plt.plot(df2['acl4_s'], df2['acl4'], label='acl4 global list')
#plt.plot(df2['acl5_s'], df2['acl5'], label='acl5 global list')
#plt.plot(df2['fw1_s'], df2['fw1'], label='fw1 global list')
#plt.plot(df2['fw2_s'], df2['fw2'], label='fw2 global list')
#plt.plot(df2['fw3_s'], df2['fw3'], label='fw3 global list')
#plt.plot(df2['fw4_s'], df2['fw4'], label='fw4 global list')
#plt.plot(df2['fw5_s'], df2['fw5'], label='fw5 global list')
#plt.plot(df2['ipc1_s'], df2['ipc1'], label='ipc1 global list')
#plt.plot(df2['ipc2_s'], df2['ipc2'], label='ipc2 global list')

plt.title(default + " vs. "+per_cpu)
#plt.title('All rule seed default locality '+locality)
#plt.title('All rule seed per cpu locality '+locality)
plt.xlabel('number of rules')
plt.ylabel('packets/sec')
plt.legend()
plt.show()
