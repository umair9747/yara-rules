rule evilnum {
    meta:
    author = "umair"
    date = "14/07/2020"
    description = "A basic YARA rule for the evilnum malware"
    strings:
        $john = "https://www.digitalpoint.com/members/johndeer123.923670/"
        $watchdog = "FC9EFBBA-78D3-438D-89AB-61990B15A100"
        $gitlab = "https://gitlab.com/jhondeer123/test/raw/master/test.py"
        $bliblobla123 = "https://gitlab.com/bliblobla123/testingtesting/"
        $pdf = "Proof of Address.pdf"
        $0x1D380 = "jifhruhajsdfg444"
        $AV = "gmts:\\\\.\\ro"

        condition:
            $john or $watchdog or $gitlab or $bliblobla123 or $pdf or $0x1D380 or $AV

}