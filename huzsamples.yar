import "pe"
import "math"
import "hash"

rule Crime_Loader_Modiloader_Delphi {
    meta:
        author = "H. A."
        date = "2025-11-16"
        description = "Detects a specific Delphi-compiled Modiloader based on hash, entry point, strings, and PE characteristics."
        family = "Modiloader"
        reference_sha256 = "b8e6e22f258512c140f2425b035f2146d6b131e5f838618e4708e1a11881512f"

    strings:
        $ep_code = { 55 8B EC 83 C4 F0 B8 6C 50 48 00 }
        $str_ole_error = "Dispatch methods do not support more than 64 parameters" wide nocase
        $str_company = "Envision Digital" wide

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        hash.sha256(0, filesize) == "b8e6e22f258512c140f2425b035f2146d6b131e5f838618e4708e1a11881512f"
        or
        (
            $ep_code at pe.entry_point and
            all of ($str_*) and
            pe.number_of_sections > 0 and
            for any i in (0..pe.number_of_sections-1): (
                pe.sections[i].name == ".text" and
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 6.0 and
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) < 7.5
            ) and
            pe.number_of_resources > 0
        )
}

rule Crime_GandCrab_v2_3r {
    meta:
        author = "H. A."
        date = "2025-11-16"
        description = "Detects GandCrab v2.3r ransomware based on hash, entry point, and characteristic strings."
        family = "GandCrab"
        version = "2.3r"
        reference_sha256_1 = "218a2e0b5d908bb14e2795765d48cc1222bf7d71dc13c765ceb5ff6acc0b825d"
        reference_sha256_2 = "70e0ffd4e8a8813a28399677051a84f235564f895f50f70a7a0016a2a537d45f"

    strings:
        $ep_code = { 55 8B EC 83 EC 0C }
        $taunt_fabian = "fabian wosar <3" ascii
        $c2_domain = "GandCrabGandCrabnomoreransom.coinomoreransom.bit" ascii

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        (
            hash.sha256(0, filesize) == "218a2e0b5d908bb14e2795765d48cc1222bf7d71dc13c765ceb5ff6acc0b825d" or
            hash.sha256(0, filesize) == "70e0ffd4e8a8813a28399677051a84f235564f895f50f70a7a0016a2a537d45f"
        )
        or
        (
            $ep_code at pe.entry_point and
            1 of ($taunt_fabian, $c2_domain) and
            pe.number_of_sections > 0 and
            for any i in (0..pe.number_of_sections-1): (
                pe.sections[i].name == ".text" and
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) < 7.0
            ) and
            pe.number_of_sections >= 3 and
            pe.number_of_resources > 0
        )
}

rule Crime_GandCrab_Hybrid_v3 {
    meta:
        author = "H. A."
        date = "2025-11-16"
        description = "Detects GandCrab hybrid variant with indicators from v2 and v5 eras."
        family = "GandCrab"
        version = "Hybrid v2/v5"
        reference_sha256 = "8cc3137fdab8596d96cff1a01aad8f7a382fc73784ec5e9b8a54b6028e2cb2a5"

    strings:
        $ep_code = { 55 8B EC 83 EC 4C }
        $taunt_fabian = "fabian wosar <3" ascii
        $c2_string = "malwarehunterteaGandCrabGandCrabpolitiaromana.bi" ascii

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        hash.sha256(0, filesize) == "8cc3137fdab8596d96cff1a01aad8f7a382fc73784ec5e9b8a54b6028e2cb2a5"
        or
        (
            $ep_code at pe.entry_point and
            1 of ($taunt_fabian, $c2_string) and
            pe.number_of_sections > 0 and
            pe.sections[0].name == ".text" and
            math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) < 7.0 and
            pe.number_of_resources > 0
        )
}

rule Crime_GandCrab_v5_2 {
    meta:
        author = "H. A."
        date = "2025-11-16"
        description = "Detects GandCrab v5.2 ransomware based on unique entry point JMP and specific strings."
        family = "GandCrab"
        version = "5.2"
        reference_sha256 = "017b236bf38a1cf9a52fc0bdee2d5f23f038b00f9811c8a58b8b66b1c756b8d6"

    strings:
        $ep_code_jmp = { E9 4B EB FF FF }
        $mutex_avers = "AversSucksForever" wide
        $note_manual = "-MANUAL.txt" wide

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        hash.sha256(0, filesize) == "017b236bf38a1cf9a52fc0bdee2d5f23f038b00f9811c8a58b8b66b1c756b8d6"
        or
        (
            $ep_code_jmp at pe.entry_point and
            1 of ($mutex_avers, $note_manual) and
            pe.number_of_sections > 0 and
            pe.sections[0].name == ".text" and
            math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) < 7.0 and
            pe.number_of_resources >= 0
        )
}

rule Crime_GandCrab_Family_Generic {
    meta:
        author = "H. A."
        date = "2025-11-16"
        description = "Generic detection for GandCrab ransomware family (all versions)."
        family = "GandCrab"
        version = "Generic"

    strings:
        $ep1 = { 55 8B EC 83 EC 0C }
        $ep2 = { 55 8B EC 83 EC 4C }
        $ep3 = { E9 4B EB FF FF }
        $taunt_fabian = "fabian wosar <3" ascii
        $gandcrab_str1 = "GandCrab" ascii nocase
        $c2_pattern1 = /[a-z]{10,30}\.bit/ ascii
        $mutex_avers = "AversSucksForever" wide
        $ransom_note = /-MANUAL\.txt/ wide
        $c2_nomoreransom = "nomoreransom" ascii nocase

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        pe.number_of_sections > 0 and
        1 of ($ep*) at pe.entry_point and
        2 of ($taunt_fabian, $gandcrab_str1, $c2_pattern1, $mutex_avers, $ransom_note, $c2_nomoreransom) and
        for any i in (0..pe.number_of_sections-1): (
            pe.sections[i].name == ".text" and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 5.0 and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) < 7.5
        ) and
        pe.number_of_resources >= 0
}
