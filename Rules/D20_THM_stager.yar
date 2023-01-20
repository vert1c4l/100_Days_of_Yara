rule THM_stager 
{
    meta:
        author = "Vertica1"
        date = "2023-01-20"
        desc = "Detect stager - file 'sshkey.php'"
        version = "1.0"
        daysofyara = "20/100"
        score = 80
    strings:
        $s1 = "Invoke-WebRequest 10.50.104.7:8000"
        $s2 = "$payload = \".\\notashell.exe"
        $s3 = "$execution_command(\"$init $payload"
        $s4 = "execute_stager("
    condition:
        2 of them and filesize < 1KB
}
