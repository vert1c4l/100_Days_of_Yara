rule MISC_Rick_Roll 
{
        meta:
                author = "ДАЗ"
                description = "Highlight links to Rick Astley's hit song on YouTube.  Official account only."
                date = "2023-02-06"
                version = "1.0"
                daysofyara = "37/100"
        strings:
                $yt = "dQw4w9WgXcQ"
                $yt_animated = "LLFhKaqnWwk"
        condition:
                uint16be(0x37) == 0x5b49 and any of them
}
