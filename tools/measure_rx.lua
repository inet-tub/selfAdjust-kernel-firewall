package.path = package.path ..";?.lua;test/?.lua;app/?.lua;/opt/pktgen-21.11.0/?.lua"

require "Pktgen"

file=io.open("/home/client/firewall/tools/stats.txt","w");
io.output(file);
pktgen.clr()
pktgen.set("1", "rate", 16);
pktgen.start("1")
sum=0
runs=10
for i=0,runs,1
do
	--printf("stats_%02d",i)
	--prints("",pktgen.portStats("0", "rate"));
	pktgen.delay(1000);
	sum =sum+pktgen.portStats("0","rate")[0]["pkts_rx"];
end
printf("%d\n",sum);
pktgen.quit()
