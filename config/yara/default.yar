rule Argus_EICAR_Test_String
{
    meta:
        description = "Detects the standard EICAR antivirus test string"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" nocase
    condition:
        $eicar
}

rule Argus_Embedded_Script_In_Image_Container
{
    meta:
        description = "Flags obvious script tags appended to an image container"
    strings:
        $script = /<script[\s>]/ nocase
        $eval = /eval\s*\(/ nocase
    condition:
        (uint16(0) == 0xD8FF or uint32(0) == 0x89504E47 or uint32(0) == 0x47494638) and any of them
}
