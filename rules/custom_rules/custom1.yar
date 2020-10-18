rule testingRuleName  :  test_tag
{
	meta:
		author = "yeet"
		purpose = "something"

	strings:
		$hey  = " ni mama"
		$nope  = " bruh"

	condition:
		1 of them
}