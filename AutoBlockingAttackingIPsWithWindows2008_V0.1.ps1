#修改应用服务端口号
#启动本脚本在命令行中运行： powershell.exe –file WIN2008_FW_Auto_Blocking_attacking_IP.ps1
#终止脚本：CTRL+C
#调整powershell安全策略 set-executionpolicy remotesigned
 $tick = 0;
 "Start to run at: " + (get-date);
  
 $regex1 = [regex] "172\.31\.1\.215:3389\s+(\d+\.\d+\.\d+\.\d+)";
 $regex2 = [regex] "Source Network Address:\t(\d+\.\d+\.\d+\.\d+)";
  
 while($True) {
  $blacklist = @();
  "Running... (tick:" + $tick + ")"; $tick+=1;

 #Port 3389
 $a = @();
 netstat -no | Select-String ":3389" | ? { $m = $regex1.Match($_); $ip = $m.Groups[1].Value; if ($m.Success -and $ip -ne "10.1.1.10") {$a = $a + $ip;} }

 if ($a.count -gt 0) {
   $ips = get-eventlog Security -Newest 1000 | Where-Object {$_.EventID -eq 4625 -and { $_.Message -match "Logon Type:\s+10"} -or{ $_.Message -match "Logon Type:\s+2"} } | foreach {$m = $regex2.Match($_.Message); $ip = $m.Groups[1].Value; $ip; } | Sort-Object | Tee-Object -Variable list | Get-Unique 

   foreach ($ip in $a) { if ($ips -contains $ip) {
     if (-not ($blacklist -contains $ip)) {
       $attack_count = ($list | Select-String $ip -SimpleMatch | Measure-Object).count;
       "Found attacking IP on 3389: " + $ip + ", with count: " + $attack_count;
       if ($attack_count -ge 20) {$blacklist = $blacklist + $ip;}
     }
    }
   }
 }
  
 #Firewall change 
 #<# $current = (netsh advfirewall firewall show rule name="MY BLACKLIST" | where {$_ -match "RemoteIP"}).replace("RemoteIP:", "").replace(" ","").replace("/255.255.255.255",""); #inside $current there is no \r or \n need remove. foreach ($ip in $blacklist) { if (-not ($current -match $ip) -and -not ($ip -like "10.1.1.10")) {"Adding this IP into firewall blocklist: " + $ip; $c= 'netsh advfirewall firewall set rule name="MY BLACKLIST" new RemoteIP="{0},{1}"' -f $ip, $current; Invoke-Expression $c; } } #> 
   
 foreach ($ip in $blacklist) {
   $fw=New-object –comObject HNetCfg.FwPolicy2;
   $myrule = $fw.Rules | where {$_.Name -eq "MY BLACKLIST"} | select -First 1; # Potential bug here?

   if (-not ($myrule.RemoteAddresses -match $ip) -and -not ($ip -like "10.1.1.10")) {
		"Adding this IP into firewall blocklist: " + $ip;
		$myrule.RemoteAddresses+=(","+$ip);
     }
 }
  
 Wait-Event -Timeout 30;#pause 30 secs 
  
 } # end of top while loop. 