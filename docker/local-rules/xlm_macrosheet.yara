rule XLM_Hidden_Macrosheet : maldoc heuristic suspicious {
    meta:
        description = "Hidden Excel-4.0 macrosheet detected"
        score = 60
    strings:
        $marker = "XLM-HIDDEN-MACROSHEET"
        $vh = "veryHidden"
        $h  = "hidden"
    condition:
        $marker and ($vh or $h)
}
