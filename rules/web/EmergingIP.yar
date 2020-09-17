rule testIP
{
	meta:
		author="Yeet"
		description="Test for suspicious IP addresses"
	strings:
		$a="103.111.83.246"
		$b="104.161.32.102"
		$c="104.130.169.84"

	condition:
		$a or $b or $c
}
