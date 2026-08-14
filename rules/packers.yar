// Packer / protector detection rules.
// meta.weight feeds the verdict engine directly (see verdict.py).

rule UPX_Packed : packer
{
    meta:
        description = "UPX-packed PE (section names + loader stub magic)"
        weight = 12
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $magic = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule MPRESS_Packed : packer
{
    meta:
        description = "MPRESS-packed PE"
        weight = 12
    strings:
        $s1 = "MPRESS1" ascii
        $s2 = "MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
