rule smbimplant {
	meta:
		author = "Lionel PRAT"
		description = "smbimplant"
	strings:
	    $t1 = { 3c23740d3c77741d3cc8 }
	    $t2 = { c83c1d74773c0d74233c }
	condition:
		$t1 or $t2
}
