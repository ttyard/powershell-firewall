#modification your application port number
#Run Secript£º powershell.exe ¨Cfile 
#Cancel Run£ºCTRL+C
#This code has been used pactera eds data certificate to sign
#If change security policy run all local code: set-executionpolicy remotesigned
#Change 10.1.1.20 to your trust remote access IP
$tick = 0; 
"Start to run at: " + (get-date); 

#fiter 
$regex2 = [regex] "Source Network Address:\t(\d+\.\d+\.\d+\.\d+)"; 
$regex3 = [regex] "CLIENT: (\d+\.\d+\.\d+\.\d+)";
  
while($True) {
	"Running... (tick:" + $tick + ")"; $tick+=1; 
	$blacklist = @();

	#Get System FW Blocked IPs
	$fwDefault=New-object -comObject HNetCfg.FwPolicy2;
	$myruleBlockIPs = ($fwDefault.Rules | where {$_.Name -eq "MY BLACKLIST"} | select -First 1).RemoteAddresses;

	#Port 3389 
	$a = netstat -ant | Select-String ":3389";

	if ($a.count -gt 0) {    
		$ips = get-eventlog Security -Newest 1000 | Where-Object {$_.EventID -eq 4625 -and $_.Message -match "Logon Type:\s+10"} | foreach {
			$m = $regex2.Match($_.Message); $ip = $m.Groups[1].Value; $ip; 
		} | Sort-Object | Tee-Object -Variable list | Get-Unique

		foreach ($ip in $ips) {
			if ((-not ($myruleBlockIPs -match $ip))) {
				$attack_count = ($list | Select-String $ip -SimpleMatch | Measure-Object).count;
				"Found attacking IP on 3389: " + $ip + ", with count: " + $attack_count;
				if ($attack_count -ge 8) {$blacklist = $blacklist + $ip;}
			}
		}
	}

	#Get MSSQLSERVER Audits Failed List
	$mssqlserver=(netstat -ant | Select-String ":1433");

	if ($mssqlserver.count -gt 0) {
		$ips = get-eventlog Application -Newest 1000 | Where-Object {$_.EventID -eq 18456} | foreach {
				$m = $regex3.Match($_.Message);
				$ip = $m.Groups[1].Value;
				$ip;
			} | Sort-Object | Tee-Object -Variable list | Get-Unique

		foreach ($ip in $ips) {
			if ((-not ($blacklist -contains $ip)) -and (-not ($myruleBlockIPs -match $ip))) {
				$attack_count = ($list | Select-String $ip -SimpleMatch | Measure-Object).count;
				"Found attacking MS-SQLServer IP on 1433: " + $ip + ", with count: " + $attack_count;
				if ($attack_count -ge 8) {$blacklist = $blacklist + $ip;}
			}
		}
	}

	#Firewall change 
	foreach ($ip in $blacklist) {
		$fw=New-object -comObject HNetCfg.FwPolicy2;
		$myrule = $fw.Rules | where {$_.Name -eq "MY BLACKLIST"} | select -First 1;   
		if (-not ($myrule.RemoteAddresses -match $ip) -and -not ($ip -like "10.1.1.20")) {
			(get-date)+"   "+"Adding this IP into firewall blocklist: " + $ip;   
			$myrule.RemoteAddresses+=(","+$ip); 
		}
	}

	Wait-Event -Timeout 30 #pause 30 secs
} # end of top while loop.