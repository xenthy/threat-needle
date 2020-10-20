rule signature:tag{
	strings:
		$ffd8e1 = "jpg"
		$ffd8e0 = "jpeg"
		$8950 = "png"
		$4749 = "gif"
		$25504446 = "pdf"
		$504b0304 = "docx"
	condition:
		1 of them
}
