// Combo Lab01-01

rule Malware_TwoStage_Backdoor_Lab01_01
{
    meta:
        description = "Detect two specific file which identified as a malware"
        author      = "Raja x NewbieGanas"
        date        = "2025-07-24"
        reference   = "Noctra Lupra Community, Gemini AI"

    strings:
        // String .exe
        $loader_mutex = "WARNING_THIS_WILL_DESTROY_YOUR_MACHINE"
        $loader_dll_typo = "kerne132.dll" ascii

        // String .dll
        $payload_mutex = "SADFHUHF" ascii
        $payload_ip = "127.26.152.13" ascii
        $payload_beacon = "hello" ascii

    condition:
        uint16(0) == 0x5a4d and
        (
            ($loader_mutex and $loader_dll_typo)
            or
            ($payload_mutex and $payload_ip)
        )
}

// Lab01-02

rule Malware_Packed_Service_Lab01_02
{
    meta:
        description = "Detect a suspicious file which is identified as a malware"
        author      = "Raja x NewbieGanas"
        date        = "2025-07-24"
        reference   = "Noctra Lupra Community, Gemini AI"

    strings:
        // Indikator Packer UPX
        $upx1 = "UPX0" ascii
        $upx2 = "UPX!" ascii

        // Indikator Behavior
        $behavior_service = "MalService" ascii
        $behavior_mutex = "sHGL345" ascii
        $behavior_url = "wareanalysisbook.com" ascii
        $behavior_useragent = "Int6net Explo!r 8FEI" ascii

    condition:
        uint16(0) == 0x5a4d and
        all of ($upx*) and
        2 of ($behavior_*)
}