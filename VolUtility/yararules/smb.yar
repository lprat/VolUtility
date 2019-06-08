rule smbimplant {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "smbimplant"
	strings:
	    $t1 = { 3c23740d3c77741d3cc8 }
	    $t2 = { c83c1d74773c0d74233c }
	condition:
		$t1 or $t2
}

rule smbimplant2 {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "https://www.countercept.com/blog/doublepulsar-usermode-analysis-generic-reflective-dll-loader/"
	strings:
	    $t1 = { f3 aa 58 41 5f 41 5e 41 5d 41 5c 5e 5f 5d 5b c3 eb 08 }
	condition:
		$t1
}

