rule emotet {
    meta:
    author = "umair"
    date = "09/09/2020"
    description = "A basic YARA rule to detect an Emotet trojan sample"
    strings:
        $AVCArray = ".?AV?$CArray@W4LoadArrayObjType@CArchive@@ABW412@@@"
        $randomstring1 = "DDltyusifghffDDCseRFFF"
        $randomstring2 = "O8#9u0VJIUe?X04(VY3i9$&tGBuVwuIzN!HM40Thii$305<CfBjZQrfhKayoSrgScUWL$d3p0hPUM$#YHstO1nzJN0zL2pDEYcz0W8G"
        $AVCCMDCMXCfgApp = ".?AVCCMDCMXCfgApp@@"
        $AccessibleProxy = ".?AV?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@"
        condition:
        $AVCArray or $randomstring1 or $randomstring2 or $AVCCMDCMXCfgApp or $AccessibleProxy
}