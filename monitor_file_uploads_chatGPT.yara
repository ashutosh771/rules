rule Monitor_File_Uploads_To_ChatGPT {
    meta:
        author = "Ashutosh Barot | @ashu_barot "
        description = "This rule watches for File uploads to chatGPT [Experimental Rule]"
        reference = "https://github.com/ashutosh771/rules/blob/main/monitor_file_uploads_chatGPT.yara"
        date = "29-Sep-2023"
  
    strings:
        $domain = "Host: chat.openai.com" ascii
        $path = "POST /backend-api/files" ascii

    condition:
        $domain and $path
}
